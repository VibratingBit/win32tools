#include <win32tools/Network/IocpTcpClient.hpp>

#include <process.h>
#include <cstring>

namespace w32t {

    IocpTcpClient::IocpTcpClient()
    {
        m_running.store(0);
        m_connected.store(0);
        m_closed.store(0);
        m_stagingLen = 0;
        std::memset(m_staging, 0, sizeof(m_staging));
        std::memset(&m_recvWsa, 0, sizeof(m_recvWsa));
        std::memset(m_recvData, 0, sizeof(m_recvData));
        InitializeSListHead(&m_pool);
        pool_init(m_pool, 32);
    }

    IocpTcpClient::~IocpTcpClient() noexcept
    {
        disconnect();
        pool_drain(m_pool);
    }

    // ─────────────────────────────────────────────────────────────────────────────
    //  connect
    // ─────────────────────────────────────────────────────────────────────────────

    bool IocpTcpClient::connect(const std::string &ip, uint16_t port,
        const TcpClientCallbacks &cb) noexcept
    {
        m_cb = cb;
        m_remoteIp = ip;
        m_remotePort = port;

        m_sock = WSASocketW(AF_INET, SOCK_STREAM, IPPROTO_TCP,
            nullptr, 0, WSA_FLAG_OVERLAPPED);
        if (m_sock == INVALID_SOCKET) {
            m_lastErr = WSAGetLastError();
            return false;
        }

        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port);
        if (inet_pton(AF_INET, ip.c_str(), &addr.sin_addr) != 1) {
            closesocket(m_sock);
            m_sock = INVALID_SOCKET;
            return false;
        }

        if (::connect(m_sock, reinterpret_cast<const sockaddr *>(&addr),
            sizeof(addr)) == SOCKET_ERROR) {
            m_lastErr = WSAGetLastError();
            closesocket(m_sock);
            m_sock = INVALID_SOCKET;
            return false;
        }

        m_iocp = CreateIoCompletionPort(INVALID_HANDLE_VALUE, nullptr, 0, 0);
        if (!m_iocp) {
            m_lastErr = static_cast<int>(GetLastError());
            closesocket(m_sock);
            m_sock = INVALID_SOCKET;
            return false;
        }

        if (!CreateIoCompletionPort(reinterpret_cast<HANDLE>(m_sock),
            m_iocp, 1, 0)) {
            m_lastErr = static_cast<int>(GetLastError());
            CloseHandle(m_iocp); m_iocp = nullptr;
            closesocket(m_sock); m_sock = INVALID_SOCKET;
            return false;
        }

        m_running.store(1);
        m_connected.store(1);
        m_closed.store(0);

        m_worker = reinterpret_cast<HANDLE>(
            _beginthreadex(nullptr, 0, workerThread, this, 0, nullptr));

        if (!postRecv()) {
            disconnect();
            return false;
        }

        if (m_cb.on_connect) m_cb.on_connect();
        return true;
    }

    // ─────────────────────────────────────────────────────────────────────────────
    //  send
    // ─────────────────────────────────────────────────────────────────────────────

    int IocpTcpClient::send(const void *data, int len) noexcept
    {
        if (!m_connected.load() || m_closed.load()) return -1;
        if (!data || len <= 0 || len > static_cast<int>(kMaxPayload)) return -1;

        SendReq *req = pool_acquire(m_pool);
        if (!req) return -1;

        std::memset(&req->op.ov, 0, sizeof(OVERLAPPED));
        req->op.type = IocpOpType::Send;

        if (m_protocol == NetProtocol::Packet ||
            m_protocol == NetProtocol::Unknown) {
            std::uint32_t hdr = static_cast<std::uint32_t>(len);
            std::memcpy(req->data, &hdr, 4);
            std::memcpy(req->data + 4, data, static_cast<std::size_t>(len));
            req->wsa.len = static_cast<ULONG>(len + 4);
        }
        else {
            const char *src = static_cast<const char *>(data);
            char *dst = req->data;
            int         out = 0;
            for (int i = 0; i < len; ++i) {
                if (src[i] == '\n' && (i == 0 || src[i - 1] != '\r'))
                    dst[out++] = '\r';
                dst[out++] = src[i];
            }
            req->wsa.len = static_cast<ULONG>(out);
        }
        req->wsa.buf = req->data;

        int rc = WSASend(m_sock, &req->wsa, 1, nullptr, 0,
            &req->op.ov, nullptr);
        DWORD err = WSAGetLastError();
        if (rc == SOCKET_ERROR && err != WSA_IO_PENDING) {
            m_lastErr = static_cast<int>(err);
            pool_release(m_pool, req);
            return -1;
        }
        return 0;
    }

    // ─────────────────────────────────────────────────────────────────────────────
    //  disconnect  (idempotent)
    // ─────────────────────────────────────────────────────────────────────────────

    void IocpTcpClient::disconnect() noexcept { closeInternal(); }

    void IocpTcpClient::closeInternal() noexcept
    {
        if (m_closed.exchange(1) != 0) return;

        m_connected.store(0);

        if (m_sock != INVALID_SOCKET) {
            shutdown(m_sock, SD_BOTH);
            closesocket(m_sock);
            m_sock = INVALID_SOCKET;
        }

        if (m_cb.on_close) m_cb.on_close();

        m_running.store(0);

        if (m_iocp) {
            PostQueuedCompletionStatus(m_iocp, 0, 0, nullptr);
        }

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
    //  postRecv
    // ─────────────────────────────────────────────────────────────────────────────

    bool IocpTcpClient::postRecv() noexcept
    {
        if (m_closed.load()) return false;

        std::memset(&m_recvOp.ov, 0, sizeof(OVERLAPPED));
        m_recvOp.type = IocpOpType::Recv;
        m_recvWsa.buf = m_recvData;
        m_recvWsa.len = static_cast<ULONG>(kRecvBufSize);

        DWORD flags = 0;
        int rc = WSARecv(m_sock, &m_recvWsa, 1, nullptr, &flags,
            &m_recvOp.ov, nullptr);
        DWORD err = WSAGetLastError();
        if (rc == SOCKET_ERROR && err != WSA_IO_PENDING) {
            m_lastErr = static_cast<int>(err);
            return false;
        }
        return true;
    }

    // ─────────────────────────────────────────────────────────────────────────────
    //  processStaging
    // ─────────────────────────────────────────────────────────────────────────────

    void IocpTcpClient::processStaging() noexcept
    {
        if (m_protocol == NetProtocol::Unknown && m_stagingLen > 0)
            m_protocol = detectProtocol(
                static_cast<std::uint8_t>(m_staging[0]));

        while (m_stagingLen > 0) {
            if (m_protocol == NetProtocol::Telnet) {
                char *nl = static_cast<char *>(
                    std::memchr(m_staging, '\n',
                        static_cast<std::size_t>(m_stagingLen)));
                if (!nl) break;

                int lineLen = static_cast<int>(nl - m_staging);
                if (lineLen > 0 && m_staging[lineLen - 1] == '\r') --lineLen;

                if (m_cb.on_data) m_cb.on_data(m_staging, lineLen);

                int consumed = static_cast<int>(nl - m_staging) + 1;
                m_stagingLen -= consumed;
                if (m_stagingLen > 0)
                    std::memmove(m_staging, m_staging + consumed,
                        static_cast<std::size_t>(m_stagingLen));
            }
            else {
                if (m_stagingLen < 4) break;

                std::uint32_t payloadLen = 0;
                std::memcpy(&payloadLen, m_staging, 4);

                if (payloadLen == 0 || payloadLen > kMaxPayload) {
                    closeInternal();
                    return;
                }
                if (m_stagingLen < static_cast<int>(payloadLen + 4)) break;

                if (m_cb.on_data)
                    m_cb.on_data(m_staging + 4, static_cast<int>(payloadLen));

                int consumed = static_cast<int>(payloadLen + 4);
                m_stagingLen -= consumed;
                if (m_stagingLen > 0)
                    std::memmove(m_staging, m_staging + consumed,
                        static_cast<std::size_t>(m_stagingLen));
            }
        }
    }

    // ─────────────────────────────────────────────────────────────────────────────
    //  Worker thread
    // ─────────────────────────────────────────────────────────────────────────────

    unsigned __stdcall IocpTcpClient::workerThread(void *arg)
    {
        auto *self = static_cast<IocpTcpClient *>(arg);

        while (self->m_running.load()) {
            DWORD      bytes = 0;
            ULONG_PTR  key = 0;
            OVERLAPPED *ov = nullptr;

            BOOL ok = GetQueuedCompletionStatus(
                self->m_iocp, &bytes, &key, &ov, INFINITE);

            if (!ov) break;  // shutdown sentinel

            auto *op = reinterpret_cast<IocpOp *>(ov);

            if (!ok || bytes == 0) {
                if (op->type == IocpOpType::Send)
                    pool_release(self->m_pool,
                        reinterpret_cast<SendReq *>(
                            reinterpret_cast<char *>(op) -
                            offsetof(SendReq, op)));
                self->closeInternal();
                break;
            }

            if (op->type == IocpOpType::Recv) {
                if (self->m_stagingLen + static_cast<int>(bytes) <=
                    static_cast<int>(kStagingSize)) {
                    std::memcpy(self->m_staging + self->m_stagingLen,
                        self->m_recvData, bytes);
                    self->m_stagingLen += static_cast<int>(bytes);
                    self->processStaging();
                }
                else {
                    self->closeInternal();
                    break;
                }
                if (!self->postRecv()) { self->closeInternal(); break; }

            }
            else {  // Send complete
                pool_release(self->m_pool,
                    reinterpret_cast<SendReq *>(
                        reinterpret_cast<char *>(op) -
                        offsetof(SendReq, op)));
            }
        }
        return 0;
    }

    // ─────────────────────────────────────────────────────────────────────────────
    //  lastError
    // ─────────────────────────────────────────────────────────────────────────────

    std::string IocpTcpClient::lastError() const noexcept
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