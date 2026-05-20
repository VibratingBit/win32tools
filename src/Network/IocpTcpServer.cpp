#include <win32tools/Network/IocpTcpServer.hpp>

#include <process.h>
#include <cstring>
#include <algorithm>
#include <iostream>

namespace w32t {

    // ─────────────────────────────────────────────────────────────────────────────
    //  Construction / destruction
    // ─────────────────────────────────────────────────────────────────────────────

    IocpTcpServer::IocpTcpServer()
    {
        m_running.store(0);
        m_clientCount.store(0);
        InitializeCriticalSection(&m_regLock);
        InitializeSListHead(&m_pool);
    }

    IocpTcpServer::~IocpTcpServer() noexcept
    {
        shutdown();
        DeleteCriticalSection(&m_regLock);
    }

    // ─────────────────────────────────────────────────────────────────────────────
    //  init
    // ─────────────────────────────────────────────────────────────────────────────

    bool IocpTcpServer::init(const TcpServerCallbacks &cb, int workerCount) noexcept
    {
        m_cb = cb;

        if (workerCount <= 0) {
            SYSTEM_INFO si{};
            GetSystemInfo(&si);
            workerCount = static_cast<int>(si.dwNumberOfProcessors);
        }

        m_iocp = CreateIoCompletionPort(INVALID_HANDLE_VALUE, nullptr, 0, 0);
        if (!m_iocp) { m_lastErr = static_cast<int>(GetLastError()); return false; }

        pool_init(m_pool, kPoolInitial);

        m_workers = static_cast<HANDLE *>(
            malloc(sizeof(HANDLE) * static_cast<std::size_t>(workerCount)));
        if (!m_workers) return false;

        m_workerCount = workerCount;
        m_running.store(1);

        for (int i = 0; i < workerCount; ++i) {
            m_workers[i] = reinterpret_cast<HANDLE>(
                _beginthreadex(nullptr, 0, workerThread, this, 0, nullptr));
            if (!m_workers[i]) return false;
        }

        m_timerThread = reinterpret_cast<HANDLE>(
            _beginthreadex(nullptr, 0, timerThread, this, 0, nullptr));

        return true;
    }

    // ─────────────────────────────────────────────────────────────────────────────
    //  listen  (blocking accept loop — call from a dedicated thread)
    // ─────────────────────────────────────────────────────────────────────────────

    bool IocpTcpServer::listen(uint16_t port,
        LPTHREAD_START_ROUTINE legacyWorker,
        const char *ip) noexcept
    {
        // server.listen(port, iocpWorkerFn)  — init + bind + one accept.
        if (legacyWorker) {
            if (!m_iocp) {
                TcpServerCallbacks empty{};
                if (!init(empty, 1)) return false;
            }
            // Bind and listen.
            SOCKET ls = WSASocketW(AF_INET, SOCK_STREAM, IPPROTO_TCP,
                nullptr, 0, WSA_FLAG_OVERLAPPED);
            if (ls == INVALID_SOCKET) return false;
            m_listenSock = ls;

            sockaddr_in addr{};
            addr.sin_family = AF_INET;
            addr.sin_port = htons(port);
            inet_pton(AF_INET, ip, &addr.sin_addr);

            int opt = 1;
            setsockopt(ls, SOL_SOCKET, SO_REUSEADDR,
                reinterpret_cast<const char *>(&opt), sizeof(opt));

            if (::bind(ls, reinterpret_cast<sockaddr *>(&addr), sizeof(addr)) ||
                ::listen(ls, SOMAXCONN)) {
                m_lastErr = WSAGetLastError();
                closesocket(ls);
                m_listenSock = INVALID_SOCKET;
                return false;
            }
            m_boundPort = port;
            m_boundIp = ip;

            // Associate IOCP with the worker the caller supplied.
            // Fire the legacy worker thread via the IOCP handle.
            HANDLE wt = CreateThread(nullptr, 0, legacyWorker, m_iocp, 0, nullptr);
            if (wt) CloseHandle(wt);
            return true;
        }

        // Normal path: must call init() first.
        SOCKET ls = WSASocketW(AF_INET, SOCK_STREAM, IPPROTO_TCP,
            nullptr, 0, WSA_FLAG_OVERLAPPED);
        if (ls == INVALID_SOCKET) { m_lastErr = WSAGetLastError(); return false; }
        m_listenSock = ls;

        int opt = 1;
        setsockopt(ls, SOL_SOCKET, SO_REUSEADDR,
            reinterpret_cast<const char *>(&opt), sizeof(opt));

        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port);
        inet_pton(AF_INET, ip, &addr.sin_addr);

        if (::bind(ls, reinterpret_cast<sockaddr *>(&addr), sizeof(addr)) ||
            ::listen(ls, SOMAXCONN)) {
            m_lastErr = WSAGetLastError();
            closesocket(ls);
            m_listenSock = INVALID_SOCKET;
            return false;
        }
        m_boundPort = port;
        m_boundIp = ip;

        // Blocking accept loop.
        while (m_running.load()) {
            SOCKET client = ::accept(ls, nullptr, nullptr);
            if (client == INVALID_SOCKET) break;

            TcpClient *c = createClient(client);
            if (!c) closesocket(client);
        }

        closesocket(ls);
        m_listenSock = INVALID_SOCKET;
        return true;
    }

    bool IocpTcpServer::accept(Socket & /*outSock*/) noexcept
    {
        if (m_listenSock == INVALID_SOCKET) return false;
        SOCKET client = ::accept(m_listenSock, nullptr, nullptr);
        if (client == INVALID_SOCKET) { m_lastErr = WSAGetLastError(); return false; }
        TcpClient *c = createClient(client);
        if (!c) { closesocket(client); return false; }
        return true;
    }

    // ─────────────────────────────────────────────────────────────────────────────
    //  stop / shutdown
    // ─────────────────────────────────────────────────────────────────────────────

    void IocpTcpServer::stop() noexcept
    {
        SOCKET ls = m_listenSock;
        if (ls != INVALID_SOCKET) {
            m_listenSock = INVALID_SOCKET;
            closesocket(ls);
        }
    }

    void IocpTcpServer::shutdown() noexcept
    {
        if (!m_running.exchange(0)) return;

        stop();

        if (m_iocp) {
            for (int i = 0; i < m_workerCount; ++i)
                PostQueuedCompletionStatus(m_iocp, 0, 0, nullptr);
        }

        for (int i = 0; i < m_workerCount; ++i) {
            if (m_workers[i]) {
                WaitForSingleObject(m_workers[i], INFINITE);
                CloseHandle(m_workers[i]);
            }
        }
        free(m_workers);
        m_workers = nullptr;
        m_workerCount = 0;

        if (m_timerThread) {
            WaitForSingleObject(m_timerThread, INFINITE);
            CloseHandle(m_timerThread);
            m_timerThread = nullptr;
        }

        pool_drain(m_pool);

        if (m_iocp) { CloseHandle(m_iocp); m_iocp = nullptr; }
    }

    // ─────────────────────────────────────────────────────────────────────────────
    //  Registry
    // ─────────────────────────────────────────────────────────────────────────────

    void IocpTcpServer::registryAdd(TcpClient *c) noexcept
    {
        EnterCriticalSection(&m_regLock);
        c->next = m_head;
        c->prev = nullptr;
        if (m_head) m_head->prev = c;
        m_head = c;
        m_clientCount.fetch_add(1);
        LeaveCriticalSection(&m_regLock);
    }

    void IocpTcpServer::registryRemove(TcpClient *c) noexcept
    {
        EnterCriticalSection(&m_regLock);
        if (c->prev) c->prev->next = c->next;
        if (c->next) c->next->prev = c->prev;
        if (m_head == c) m_head = c->next;
        c->next = c->prev = nullptr;
        m_clientCount.fetch_sub(1);
        LeaveCriticalSection(&m_regLock);
    }

    // ─────────────────────────────────────────────────────────────────────────────
    //  Ref counting
    // ─────────────────────────────────────────────────────────────────────────────

    void IocpTcpServer::acquire(TcpClient *c) noexcept
    {
        c->refs.fetch_add(1);
    }

    void IocpTcpServer::release(TcpClient *c) noexcept
    {
        if (c->refs.fetch_sub(1) == 1)
            delete c;
    }

    // ─────────────────────────────────────────────────────────────────────────────
    //  createClient
    // ─────────────────────────────────────────────────────────────────────────────

    TcpClient *IocpTcpServer::createClient(SOCKET s) noexcept
    {
        auto *c = new(std::nothrow) TcpClient{};
        if (!c) return nullptr;

        c->sock = s;
        c->server = this;
        c->refs.store(1);
        c->closed.store(0);

        // Capture peer info.
        sockaddr_in peer{};
        int plen = sizeof(peer);
        if (getpeername(s, reinterpret_cast<sockaddr *>(&peer), &plen) == 0) {
            inet_ntop(AF_INET, &peer.sin_addr, c->ip, sizeof(c->ip));
            c->port = ntohs(peer.sin_port);
        }
        c->arrivalTs = GetTickCount64();
        c->lastActive = c->arrivalTs;

        // Bind to IOCP with the client pointer as the completion key.
        if (!CreateIoCompletionPort(reinterpret_cast<HANDLE>(s),
            m_iocp,
            reinterpret_cast<ULONG_PTR>(c), 0)) {
            delete c;
            return nullptr;
        }

        registryAdd(c);

        if (m_cb.on_connect) m_cb.on_connect(c);

        if (!postRecv(c)) {
            closeInternal(c);
            return nullptr;
        }
        return c;
    }

    // ─────────────────────────────────────────────────────────────────────────────
    //  postRecv
    // ─────────────────────────────────────────────────────────────────────────────

    bool IocpTcpServer::postRecv(TcpClient *c) noexcept
    {
        if (c->closed.load()) return false;

        std::memset(&c->recvOp.ov, 0, sizeof(OVERLAPPED));
        c->recvOp.type = IocpOpType::Recv;
        c->recvWsa.buf = c->recvData;
        c->recvWsa.len = static_cast<ULONG>(kRecvBufSize);

        DWORD flags = 0;
        acquire(c);

        int rc = WSARecv(c->sock, &c->recvWsa, 1, nullptr, &flags,
            &c->recvOp.ov, nullptr);
        DWORD err = WSAGetLastError();

        if (rc == SOCKET_ERROR && err != WSA_IO_PENDING) {
            release(c);
            return false;
        }
        return true;
    }

    void IocpTcpServer::processStaging(TcpClient *c) noexcept
    {
        if (c->protocol == NetProtocol::Unknown && c->stagingLen > 0)
            c->protocol = detectProtocol(
                static_cast<std::uint8_t>(c->staging[0]));

        while (c->stagingLen > 0) {
            if (c->protocol == NetProtocol::Telnet) {
                char *nl = static_cast<char *>(
                    std::memchr(c->staging, '\n', static_cast<std::size_t>(c->stagingLen)));
                if (!nl) break;

                int lineLen = static_cast<int>(nl - c->staging);
                if (lineLen > 0 && c->staging[lineLen - 1] == '\r') --lineLen;

                if (m_cb.on_data) m_cb.on_data(c, c->staging, lineLen);

                int consumed = static_cast<int>(nl - c->staging) + 1;
                c->stagingLen -= consumed;
                if (c->stagingLen > 0)
                    std::memmove(c->staging, c->staging + consumed,
                        static_cast<std::size_t>(c->stagingLen));
            }
            else {
                if (c->stagingLen < 4) break;

                std::uint32_t payloadLen = 0;
                std::memcpy(&payloadLen, c->staging, 4);

                if (payloadLen == 0 || payloadLen > kMaxPayload) {
                    closeInternal(c);
                    return;
                }
                if (c->stagingLen < static_cast<int>(payloadLen + 4)) break;

                if (m_cb.on_data) m_cb.on_data(c, c->staging + 4, static_cast<int>(payloadLen));

                int consumed = static_cast<int>(payloadLen + 4);
                c->stagingLen -= consumed;
                if (c->stagingLen > 0)
                    std::memmove(c->staging, c->staging + consumed,
                        static_cast<std::size_t>(c->stagingLen));
            }
        }
    }

    // ─────────────────────────────────────────────────────────────────────────────
    //  closeInternal  (idempotent)
    // ─────────────────────────────────────────────────────────────────────────────

    void IocpTcpServer::closeInternal(TcpClient *c) noexcept
    {
        if (!c || c->closed.exchange(1) != 0) return;

        registryRemove(c);
        ::shutdown(c->sock, SD_BOTH);
        closesocket(c->sock);
        c->sock = INVALID_SOCKET;

        if (m_cb.on_close) m_cb.on_close(c);

        release(c);  // drop creation ref
    }

    // ─────────────────────────────────────────────────────────────────────────────
    //  Public: send
    // ─────────────────────────────────────────────────────────────────────────────

    int IocpTcpServer::send(TcpClientHandle c, const void *data, int len) noexcept
    {
        if (!c || !data || len <= 0)        return -1;
        if (c->closed.load())               return -1;
        if (len > static_cast<int>(kMaxPayload)) return -1;

        SendReq *req = pool_acquire(m_pool);
        if (!req) return -1;

        std::memset(&req->op.ov, 0, sizeof(OVERLAPPED));
        req->op.type = IocpOpType::Send;

        if (c->protocol == NetProtocol::Packet ||
            c->protocol == NetProtocol::Unknown) {
            std::uint32_t hdr = static_cast<std::uint32_t>(len);
            std::memcpy(req->data, &hdr, 4);
            std::memcpy(req->data + 4, data, static_cast<std::size_t>(len));
            req->wsa.len = static_cast<ULONG>(len + 4);
        }
        else {
            // Telnet: normalise bare '\n' → '\r\n'.
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

        acquire(c);
        int rc = WSASend(c->sock, &req->wsa, 1, nullptr, 0, &req->op.ov, nullptr);
        DWORD err = WSAGetLastError();
        if (rc == SOCKET_ERROR && err != WSA_IO_PENDING) {
            pool_release(m_pool, req);
            release(c);
            return -1;
        }
        return 0;
    }

    // ─────────────────────────────────────────────────────────────────────────────
    //  Public: close / broadcast / registry
    // ─────────────────────────────────────────────────────────────────────────────

    void IocpTcpServer::close(TcpClientHandle c) noexcept { closeInternal(c); }

    void IocpTcpServer::broadcast(const void *data, int len) noexcept
    {
        EnterCriticalSection(&m_regLock);
        for (TcpClient *c = m_head; c; c = c->next)
            if (!c->isMuted) send(c, data, len);
        LeaveCriticalSection(&m_regLock);
    }

    void IocpTcpServer::broadcastExcept(TcpClientHandle exclude,
        const void *data, int len) noexcept
    {
        EnterCriticalSection(&m_regLock);
        for (TcpClient *c = m_head; c; c = c->next)
            if (c != exclude && !c->isMuted) send(c, data, len);
        LeaveCriticalSection(&m_regLock);
    }

    int IocpTcpServer::clientCount() const noexcept
    {
        return m_clientCount.load();
    }

    TcpClientHandle IocpTcpServer::findById(int id) const noexcept
    {
        TcpClientHandle result = nullptr;
        EnterCriticalSection(&m_regLock);
        for (TcpClient *c = m_head; c && !result; c = c->next)
            if (c->id == id) result = c;
        LeaveCriticalSection(&m_regLock);
        return result;
    }

    void IocpTcpServer::iterateClients(const IterateCb &cb) noexcept
    {
        EnterCriticalSection(&m_regLock);
        for (TcpClient *c = m_head; c;) {
            TcpClient *next = c->next;
            cb(c);
            c = next;
        }
        LeaveCriticalSection(&m_regLock);
    }

    // ─────────────────────────────────────────────────────────────────────────────
    //  Diagnostics
    // ─────────────────────────────────────────────────────────────────────────────

    std::string IocpTcpServer::localAddress() const noexcept { return m_boundIp; }
    uint16_t    IocpTcpServer::localPort()    const noexcept { return m_boundPort; }

    std::string IocpTcpServer::lastError() const noexcept
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

    // ─────────────────────────────────────────────────────────────────────────────
    //  IOCP worker thread
    // ─────────────────────────────────────────────────────────────────────────────

    unsigned __stdcall IocpTcpServer::workerThread(void *arg)
    {
        auto *srv = static_cast<IocpTcpServer *>(arg);

        while (srv->m_running.load()) {
            DWORD      bytes = 0;
            ULONG_PTR  key = 0;
            OVERLAPPED *ov = nullptr;

            BOOL ok = GetQueuedCompletionStatus(
                srv->m_iocp, &bytes, &key, &ov, INFINITE);

            if (!ov) break;  // null overlapped = shutdown sentinel

            auto *c = reinterpret_cast<TcpClient *>(key);
            auto *op = reinterpret_cast<IocpOp *>(ov);

            if (!ok || bytes == 0) {
                srv->closeInternal(c);
                if (op->type == IocpOpType::Send)
                    pool_release(srv->m_pool,
                        reinterpret_cast<SendReq *>(
                            reinterpret_cast<char *>(op) -
                            offsetof(SendReq, op)));
                release(c);
                continue;
            }

            if (op->type == IocpOpType::Recv) {
                c->lastActive = GetTickCount64();

                if (c->stagingLen + static_cast<int>(bytes) <=
                    static_cast<int>(kStagingSize)) {
                    std::memcpy(c->staging + c->stagingLen,
                        c->recvData, bytes);
                    c->stagingLen += static_cast<int>(bytes);
                    srv->processStaging(c);
                }
                else {
                    srv->closeInternal(c);
                }

                if (!srv->postRecv(c)) srv->closeInternal(c);

            }
            else {  // Send
                pool_release(srv->m_pool,
                    reinterpret_cast<SendReq *>(
                        reinterpret_cast<char *>(op) -
                        offsetof(SendReq, op)));
            }

            release(c);
        }
        return 0;
    }

    // ─────────────────────────────────────────────────────────────────────────────
    //  Idle-timeout timer thread
    // ─────────────────────────────────────────────────────────────────────────────

    unsigned __stdcall IocpTcpServer::timerThread(void *arg)
    {
        auto *srv = static_cast<IocpTcpServer *>(arg);

        while (srv->m_running.load()) {
            Sleep(kIdleCheckMs);
            std::uint64_t now = GetTickCount64();

            srv->iterateClients([&](TcpClientHandle c) {
                if (c->lastActive == 0) return;
                if (now - c->lastActive > kIdleTimeoutMs)
                    srv->closeInternal(c);
                });
        }
        return 0;
    }

} // namespace w32t