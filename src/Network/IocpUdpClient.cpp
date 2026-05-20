#include <win32tools/Network/IocpUdpClient.hpp>

#include <process.h>
#include <cstring>

namespace w32t {

IocpUdpClient::IocpUdpClient(int concurrentRecvs)
    : m_concurrentRecvs(concurrentRecvs > 0 ? concurrentRecvs : 2)
{
    InitializeSListHead(&m_sendPool);
    pool_init(m_sendPool, 32);
}

IocpUdpClient::~IocpUdpClient() noexcept
{
    disconnect();
    pool_drain(m_sendPool);
    delete[] m_recvOps;
}

// ─────────────────────────────────────────────────────────────────────────────
//  initIocp  (shared setup)
// ─────────────────────────────────────────────────────────────────────────────

bool IocpUdpClient::initIocp() noexcept
{
    m_iocp = CreateIoCompletionPort(INVALID_HANDLE_VALUE, nullptr, 0, 0);
    if (!m_iocp) { m_lastErr = static_cast<int>(GetLastError()); return false; }

    if (!CreateIoCompletionPort(reinterpret_cast<HANDLE>(m_sock),
                                m_iocp, 0, 0)) {
        m_lastErr = static_cast<int>(GetLastError());
        return false;
    }

    m_recvOps = new(std::nothrow) UdpClientRecvOp[
        static_cast<std::size_t>(m_concurrentRecvs)]{};
    if (!m_recvOps) return false;

    m_running.store(1);
    m_active.store(1);
    m_closed.store(0);

    m_worker = reinterpret_cast<HANDLE>(
        _beginthreadex(nullptr, 0, workerThread, this, 0, nullptr));
    if (!m_worker) return false;

    for (int i = 0; i < m_concurrentRecvs; ++i) {
        if (!postRecvFrom(&m_recvOps[i])) return false;
    }
    return true;
}

// ─────────────────────────────────────────────────────────────────────────────
//  connectTo  (connected UDP)
// ─────────────────────────────────────────────────────────────────────────────

bool IocpUdpClient::connectTo(const std::string& serverIp, uint16_t serverPort,
                               const UdpClientCallbacks& cb,
                               uint16_t localPort) noexcept
{
    m_cb = cb;

    m_sock = WSASocketW(AF_INET, SOCK_DGRAM, IPPROTO_UDP,
                        nullptr, 0, WSA_FLAG_OVERLAPPED);
    if (m_sock == INVALID_SOCKET) {
        m_lastErr = WSAGetLastError();
        return false;
    }

    // Bind to local port.
    sockaddr_in local{};
    local.sin_family      = AF_INET;
    local.sin_port        = htons(localPort);
    local.sin_addr.s_addr = INADDR_ANY;
    if (::bind(m_sock, reinterpret_cast<const sockaddr*>(&local),
               sizeof(local)) == SOCKET_ERROR) {
        m_lastErr = WSAGetLastError();
        closesocket(m_sock); m_sock = INVALID_SOCKET;
        return false;
    }

    // Capture actual local port.
    sockaddr_in bound{};
    int blen = sizeof(bound);
    if (getsockname(m_sock, reinterpret_cast<sockaddr*>(&bound), &blen) == 0)
        m_localPort = ntohs(bound.sin_port);

    // ::connect() to fix the remote address.
    sockaddr_in remote{};
    remote.sin_family = AF_INET;
    remote.sin_port   = htons(serverPort);
    if (inet_pton(AF_INET, serverIp.c_str(), &remote.sin_addr) != 1) {
        closesocket(m_sock); m_sock = INVALID_SOCKET;
        return false;
    }
    if (::connect(m_sock, reinterpret_cast<const sockaddr*>(&remote),
                  sizeof(remote)) == SOCKET_ERROR) {
        m_lastErr = WSAGetLastError();
        closesocket(m_sock); m_sock = INVALID_SOCKET;
        return false;
    }
    m_connected = true;

    return initIocp();
}

// ─────────────────────────────────────────────────────────────────────────────
//  bind  (unconnected UDP)
// ─────────────────────────────────────────────────────────────────────────────

bool IocpUdpClient::bind(uint16_t localPort, const UdpClientCallbacks& cb) noexcept
{
    m_cb = cb;

    m_sock = WSASocketW(AF_INET, SOCK_DGRAM, IPPROTO_UDP,
                        nullptr, 0, WSA_FLAG_OVERLAPPED);
    if (m_sock == INVALID_SOCKET) {
        m_lastErr = WSAGetLastError();
        return false;
    }

    sockaddr_in local{};
    local.sin_family      = AF_INET;
    local.sin_port        = htons(localPort);
    local.sin_addr.s_addr = INADDR_ANY;
    if (::bind(m_sock, reinterpret_cast<const sockaddr*>(&local),
               sizeof(local)) == SOCKET_ERROR) {
        m_lastErr = WSAGetLastError();
        closesocket(m_sock); m_sock = INVALID_SOCKET;
        return false;
    }

    sockaddr_in bound{};
    int blen = sizeof(bound);
    if (getsockname(m_sock, reinterpret_cast<sockaddr*>(&bound), &blen) == 0)
        m_localPort = ntohs(bound.sin_port);

    return initIocp();
}

// ─────────────────────────────────────────────────────────────────────────────
//  send / sendTo
// ─────────────────────────────────────────────────────────────────────────────

int IocpUdpClient::send(const void* data, int len) noexcept
{
    if (!m_connected || !m_active.load()) return -1;
    if (!data || len <= 0 || len > static_cast<int>(kRecvBufSize)) return -1;

    SendReq* req = pool_acquire(m_sendPool);
    if (!req) return -1;

    std::memset(&req->op.ov, 0, sizeof(OVERLAPPED));
    req->op.type = IocpOpType::SendTo;
    std::memcpy(req->data, data, static_cast<std::size_t>(len));
    req->wsa.buf = req->data;
    req->wsa.len = static_cast<ULONG>(len);

    // Connected socket: WSASend works without address.
    int rc = WSASend(m_sock, &req->wsa, 1, nullptr, 0,
                     &req->op.ov, nullptr);
    DWORD err = WSAGetLastError();
    if (rc == SOCKET_ERROR && err != WSA_IO_PENDING) {
        m_lastErr = static_cast<int>(err);
        pool_release(m_sendPool, req);
        return -1;
    }
    return 0;
}

int IocpUdpClient::sendTo(const sockaddr_storage& dest,
                           const void* data, int len) noexcept
{
    if (!m_active.load()) return -1;
    if (!data || len <= 0 || len > static_cast<int>(kRecvBufSize)) return -1;

    SendReq* req = pool_acquire(m_sendPool);
    if (!req) return -1;

    std::memset(&req->op.ov, 0, sizeof(OVERLAPPED));
    req->op.type = IocpOpType::SendTo;
    std::memcpy(req->data, data, static_cast<std::size_t>(len));
    req->wsa.buf = req->data;
    req->wsa.len = static_cast<ULONG>(len);

    int addrLen = (dest.ss_family == AF_INET6)
        ? static_cast<int>(sizeof(sockaddr_in6))
        : static_cast<int>(sizeof(sockaddr_in));

    int rc = WSASendTo(m_sock, &req->wsa, 1, nullptr, 0,
                       reinterpret_cast<const sockaddr*>(&dest),
                       addrLen, &req->op.ov, nullptr);
    DWORD err = WSAGetLastError();
    if (rc == SOCKET_ERROR && err != WSA_IO_PENDING) {
        m_lastErr = static_cast<int>(err);
        pool_release(m_sendPool, req);
        return -1;
    }
    return 0;
}

// ─────────────────────────────────────────────────────────────────────────────
//  disconnect / closeInternal
// ─────────────────────────────────────────────────────────────────────────────

void IocpUdpClient::disconnect() noexcept { closeInternal(); }

void IocpUdpClient::closeInternal() noexcept
{
    if (m_closed.exchange(1) != 0) return;

    m_active.store(0);

    if (m_sock != INVALID_SOCKET) {
        closesocket(m_sock);
        m_sock = INVALID_SOCKET;
    }

    if (m_cb.on_close) m_cb.on_close();

    m_running.store(0);

    if (m_iocp)
        PostQueuedCompletionStatus(m_iocp, 0, 0, nullptr);

    if (m_worker) {
        WaitForSingleObject(m_worker, INFINITE);
        CloseHandle(m_worker);
        m_worker = nullptr;
    }

    if (m_iocp) {
        CloseHandle(m_iocp);
        m_iocp = nullptr;
    }
}

// ─────────────────────────────────────────────────────────────────────────────
//  postRecvFrom
// ─────────────────────────────────────────────────────────────────────────────

bool IocpUdpClient::postRecvFrom(UdpClientRecvOp* op) noexcept
{
    if (m_closed.load()) return false;

    std::memset(&op->ov, 0, sizeof(OVERLAPPED));
    op->type    = IocpOpType::RecvFrom;
    op->wsa.buf = op->data;
    op->wsa.len = static_cast<ULONG>(kRecvBufSize);
    op->fromLen = sizeof(sockaddr_storage);

    DWORD flags = 0;
    int rc = WSARecvFrom(m_sock, &op->wsa, 1, nullptr, &flags,
                         reinterpret_cast<sockaddr*>(&op->fromAddr),
                         &op->fromLen, &op->ov, nullptr);
    DWORD err = WSAGetLastError();
    if (rc == SOCKET_ERROR && err != WSA_IO_PENDING) {
        m_lastErr = static_cast<int>(err);
        return false;
    }
    return true;
}

// ─────────────────────────────────────────────────────────────────────────────
//  Worker thread
// ─────────────────────────────────────────────────────────────────────────────

unsigned __stdcall IocpUdpClient::workerThread(void* arg)
{
    auto* self = static_cast<IocpUdpClient*>(arg);

    while (self->m_running.load()) {
        DWORD      bytes = 0;
        ULONG_PTR  key   = 0;
        OVERLAPPED* ov   = nullptr;

        BOOL ok = GetQueuedCompletionStatus(
            self->m_iocp, &bytes, &key, &ov, INFINITE);

        if (!ov) break;  // shutdown sentinel

        auto* op = reinterpret_cast<IocpOp*>(ov);

        if (op->type == IocpOpType::RecvFrom) {
            auto* rop = reinterpret_cast<UdpClientRecvOp*>(ov);
            if (ok && bytes > 0 && self->m_cb.on_data)
                self->m_cb.on_data(rop->fromAddr,
                                   rop->data,
                                   static_cast<int>(bytes));
            if (self->m_running.load())
                self->postRecvFrom(rop);

        } else {  // SendTo complete
            pool_release(self->m_sendPool,
                         reinterpret_cast<SendReq*>(
                             reinterpret_cast<char*>(op) -
                             offsetof(SendReq, op)));
        }
    }
    return 0;
}

// ─────────────────────────────────────────────────────────────────────────────
//  lastError
// ─────────────────────────────────────────────────────────────────────────────

std::string IocpUdpClient::lastError() const noexcept
{
    if (!m_lastErr) return {};
    char buf[512]{};
    FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                   nullptr, static_cast<DWORD>(m_lastErr), 0,
                   buf, static_cast<DWORD>(sizeof(buf)), nullptr);
    for (int i = static_cast<int>(strlen(buf)) - 1;
         i >= 0 && (buf[i] == '\r' || buf[i] == '\n'); --i)
        buf[i] = '\0';
    return buf;
}

} // namespace w32t