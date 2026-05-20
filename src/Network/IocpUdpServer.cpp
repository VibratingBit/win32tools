#include <win32tools/Network/IocpUdpServer.hpp>

#include <process.h>
#include <cstring>

namespace w32t {

    // ─────────────────────────────────────────────────────────────────────────────
    //  Construction / destruction
    // ─────────────────────────────────────────────────────────────────────────────

    IocpUdpServer::IocpUdpServer(int concurrentRecvs)
        : m_concurrentRecvs(concurrentRecvs > 0 ? concurrentRecvs : 4)
    {
        m_running.store(0);
        m_peerCount.store(0);
        m_nextId.store(1);
        InitializeCriticalSection(&m_peerLock);
        InitializeSListHead(&m_sendPool);
    }

    IocpUdpServer::~IocpUdpServer() noexcept
    {
        shutdown();
        DeleteCriticalSection(&m_peerLock);
    }

    // ─────────────────────────────────────────────────────────────────────────────
    //  init
    // ─────────────────────────────────────────────────────────────────────────────

    bool IocpUdpServer::init(const UdpServerCallbacks &cb, int workerCount) noexcept
    {
        m_cb = cb;

        if (workerCount <= 0) {
            SYSTEM_INFO si{};
            GetSystemInfo(&si);
            workerCount = static_cast<int>(si.dwNumberOfProcessors);
        }

        m_iocp = CreateIoCompletionPort(INVALID_HANDLE_VALUE, nullptr, 0, 0);
        if (!m_iocp) { m_lastErr = static_cast<int>(GetLastError()); return false; }

        // Allocate send pool.
        for (int i = 0; i < static_cast<int>(kPoolInitial); ++i) {
            auto *r = static_cast<SendReq *>(_aligned_malloc(sizeof(SendReq), 16));
            if (r) { new(r) SendReq{}; InterlockedPushEntrySList(&m_sendPool, &r->entry); }
        }

        // Allocate recv-op array.
        m_recvOps = new(std::nothrow) UdpRecvOp[static_cast<std::size_t>(m_concurrentRecvs)]{};
        if (!m_recvOps) return false;
        for (int i = 0; i < m_concurrentRecvs; ++i)
            m_recvOps[i].server = this;

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

        if (m_idleTimeoutMs > 0) {
            m_timerThread = reinterpret_cast<HANDLE>(
                _beginthreadex(nullptr, 0, timerThread, this, 0, nullptr));
        }

        return true;
    }

    // ─────────────────────────────────────────────────────────────────────────────
    //  listen
    // ─────────────────────────────────────────────────────────────────────────────

    bool IocpUdpServer::listen(uint16_t port, const char *ip) noexcept
    {
        m_sock = WSASocketW(AF_INET, SOCK_DGRAM, IPPROTO_UDP,
            nullptr, 0, WSA_FLAG_OVERLAPPED);
        if (m_sock == INVALID_SOCKET) {
            m_lastErr = WSAGetLastError();
            return false;
        }

        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port);
        inet_pton(AF_INET, ip, &addr.sin_addr);

        if (::bind(m_sock, reinterpret_cast<const sockaddr *>(&addr), sizeof(addr))
            == SOCKET_ERROR) {
            m_lastErr = WSAGetLastError();
            closesocket(m_sock);
            m_sock = INVALID_SOCKET;
            return false;
        }
        m_boundPort = port;

        if (!CreateIoCompletionPort(reinterpret_cast<HANDLE>(m_sock),
            m_iocp, 0, 0)) {
            m_lastErr = static_cast<int>(GetLastError());
            closesocket(m_sock);
            m_sock = INVALID_SOCKET;
            return false;
        }

        // Arm all concurrent recv operations.
        for (int i = 0; i < m_concurrentRecvs; ++i) {
            if (!postRecvFrom(&m_recvOps[i])) return false;
        }
        return true;
    }

    // ─────────────────────────────────────────────────────────────────────────────
    //  stop / shutdown
    // ─────────────────────────────────────────────────────────────────────────────

    void IocpUdpServer::stop() noexcept
    {
        if (m_sock != INVALID_SOCKET) {
            closesocket(m_sock);
            m_sock = INVALID_SOCKET;
        }
    }

    void IocpUdpServer::shutdown() noexcept
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

        delete[] m_recvOps;
        m_recvOps = nullptr;

        // Drain send pool.
        PSLIST_ENTRY e;
        while ((e = InterlockedPopEntrySList(&m_sendPool)) != nullptr)
            _aligned_free(e);

        if (m_iocp) { CloseHandle(m_iocp); m_iocp = nullptr; }

        // Free peer list.
        EnterCriticalSection(&m_peerLock);
        UdpPeer *p = m_peerHead;
        while (p) { UdpPeer *nx = p->next; delete p; p = nx; }
        m_peerHead = nullptr;
        LeaveCriticalSection(&m_peerLock);
    }

    // ─────────────────────────────────────────────────────────────────────────────
    //  postRecvFrom
    // ─────────────────────────────────────────────────────────────────────────────

    bool IocpUdpServer::postRecvFrom(UdpRecvOp *op) noexcept
    {
        std::memset(&op->ov, 0, sizeof(OVERLAPPED));
        op->type = IocpOpType::RecvFrom;
        op->wsa.buf = op->data;
        op->wsa.len = static_cast<ULONG>(kRecvBufSize);
        op->fromLen = sizeof(sockaddr_storage);

        DWORD flags = 0;
        int rc = WSARecvFrom(m_sock, &op->wsa, 1, nullptr, &flags,
            reinterpret_cast<sockaddr *>(&op->fromAddr),
            &op->fromLen,
            &op->ov, nullptr);
        DWORD err = WSAGetLastError();
        if (rc == SOCKET_ERROR && err != WSA_IO_PENDING) {
            m_lastErr = static_cast<int>(err);
            return false;
        }
        return true;
    }

    // ─────────────────────────────────────────────────────────────────────────────
    //  sendTo
    // ─────────────────────────────────────────────────────────────────────────────

    int IocpUdpServer::sendTo(const sockaddr_storage &dest,
        const void *data, int len) noexcept
    {
        if (m_sock == INVALID_SOCKET || !data || len <= 0) return -1;

        SendReq *req = pool_acquire(m_sendPool);
        if (!req) return -1;

        std::memset(&req->op.ov, 0, sizeof(OVERLAPPED));
        req->op.type = IocpOpType::SendTo;

        int copy = (len > static_cast<int>(kRecvBufSize))
            ? static_cast<int>(kRecvBufSize) : len;
        std::memcpy(req->data, data, static_cast<std::size_t>(copy));
        req->wsa.buf = req->data;
        req->wsa.len = static_cast<ULONG>(copy);

        int addrLen = (dest.ss_family == AF_INET6)
            ? static_cast<int>(sizeof(sockaddr_in6))
            : static_cast<int>(sizeof(sockaddr_in));

        int rc = WSASendTo(m_sock, &req->wsa, 1, nullptr, 0,
            reinterpret_cast<const sockaddr *>(&dest),
            addrLen, &req->op.ov, nullptr);
        DWORD err = WSAGetLastError();
        if (rc == SOCKET_ERROR && err != WSA_IO_PENDING) {
            m_lastErr = static_cast<int>(err);
            pool_release(m_sendPool, req);
            return -1;
        }
        return 0;
    }

    int IocpUdpServer::sendTo(UdpPeer *peer, const void *data, int len) noexcept
    {
        if (!peer) return -1;
        return sendTo(peer->addr, data, len);
    }

    void IocpUdpServer::broadcast(const void *data, int len) noexcept
    {
        EnterCriticalSection(&m_peerLock);
        for (UdpPeer *p = m_peerHead; p; p = p->next)
            sendTo(p->addr, data, len);
        LeaveCriticalSection(&m_peerLock);
    }

    // ─────────────────────────────────────────────────────────────────────────────
    //  Peer registry
    // ─────────────────────────────────────────────────────────────────────────────

    static bool addrEqual(const sockaddr_storage &a, const sockaddr_storage &b) noexcept
    {
        if (a.ss_family != b.ss_family) return false;
        if (a.ss_family == AF_INET) {
            const auto *a4 = reinterpret_cast<const sockaddr_in *>(&a);
            const auto *b4 = reinterpret_cast<const sockaddr_in *>(&b);
            return a4->sin_port == b4->sin_port &&
                a4->sin_addr.s_addr == b4->sin_addr.s_addr;
        }
        return std::memcmp(&a, &b, sizeof(sockaddr_storage)) == 0;
    }

    void IocpUdpServer::peerAdd(UdpPeer *p) noexcept
    {
        p->next = m_peerHead;
        p->prev = nullptr;
        if (m_peerHead) m_peerHead->prev = p;
        m_peerHead = p;
        m_peerCount.fetch_add(1);
    }

    void IocpUdpServer::peerRemove(UdpPeer *p) noexcept
    {
        if (p->prev) p->prev->next = p->next;
        if (p->next) p->next->prev = p->prev;
        if (m_peerHead == p) m_peerHead = p->next;
        m_peerCount.fetch_sub(1);
    }

    UdpPeer *IocpUdpServer::peerFind(const sockaddr_storage &addr) noexcept
    {
        for (UdpPeer *p = m_peerHead; p; p = p->next)
            if (addrEqual(p->addr, addr)) return p;
        return nullptr;
    }

    UdpPeer *IocpUdpServer::peerGetOrCreate(const sockaddr_storage &addr) noexcept
    {
        UdpPeer *p = peerFind(addr);
        if (p) return p;

        p = new(std::nothrow) UdpPeer{};
        if (!p) return nullptr;

        p->addr = addr;
        p->id = m_nextId.fetch_add(1);
        p->lastActive = GetTickCount64();

        if (addr.ss_family == AF_INET) {
            const auto *a4 = reinterpret_cast<const sockaddr_in *>(&addr);
            inet_ntop(AF_INET, &a4->sin_addr, p->ip, sizeof(p->ip));
            p->port = ntohs(a4->sin_port);
        }
        else if (addr.ss_family == AF_INET6) {
            const auto *a6 = reinterpret_cast<const sockaddr_in6 *>(&addr);
            inet_ntop(AF_INET6, &a6->sin6_addr, p->ip, sizeof(p->ip));
            p->port = ntohs(a6->sin6_port);
        }

        peerAdd(p);
        return p;
    }

    UdpPeer *IocpUdpServer::findPeer(const char *ip, int port) const noexcept
    {
        EnterCriticalSection(&m_peerLock);
        UdpPeer *result = nullptr;
        for (UdpPeer *p = m_peerHead; p && !result; p = p->next)
            if (p->port == port && strcmp(p->ip, ip) == 0)
                result = p;
        LeaveCriticalSection(&m_peerLock);
        return result;
    }

    UdpPeer *IocpUdpServer::findPeerById(int id) const noexcept
    {
        EnterCriticalSection(&m_peerLock);
        UdpPeer *result = nullptr;
        for (UdpPeer *p = m_peerHead; p && !result; p = p->next)
            if (p->id == id) result = p;
        LeaveCriticalSection(&m_peerLock);
        return result;
    }

    void IocpUdpServer::iteratePeers(const IteratePeerCb &cb) noexcept
    {
        EnterCriticalSection(&m_peerLock);
        for (UdpPeer *p = m_peerHead; p;) {
            UdpPeer *nx = p->next;
            cb(p);
            p = nx;
        }
        LeaveCriticalSection(&m_peerLock);
    }

    // ─────────────────────────────────────────────────────────────────────────────
    //  onDatagram — called from worker with each completed recv
    // ─────────────────────────────────────────────────────────────────────────────

    void IocpUdpServer::onDatagram(const char *data, int len,
        const sockaddr_storage &from) noexcept
    {
        EnterCriticalSection(&m_peerLock);
        UdpPeer *peer = peerGetOrCreate(from);
        bool isNew = false;
        if (peer) {
            isNew = (peer->lastActive == 0);
            peer->lastActive = GetTickCount64();
        }
        LeaveCriticalSection(&m_peerLock);

        if (peer && isNew && m_cb.on_new_peer)
            m_cb.on_new_peer(peer);

        if (m_cb.on_data)
            m_cb.on_data(peer, data, len);
    }

    // ─────────────────────────────────────────────────────────────────────────────
    //  Worker thread
    // ─────────────────────────────────────────────────────────────────────────────

    unsigned __stdcall IocpUdpServer::workerThread(void *arg)
    {
        auto *srv = static_cast<IocpUdpServer *>(arg);

        while (srv->m_running.load()) {
            DWORD      bytes = 0;
            ULONG_PTR  key = 0;
            OVERLAPPED *ov = nullptr;

            BOOL ok = GetQueuedCompletionStatus(
                srv->m_iocp, &bytes, &key, &ov, INFINITE);

            if (!ov) break;  // shutdown sentinel

            auto *op = reinterpret_cast<IocpOp *>(ov);

            if (op->type == IocpOpType::RecvFrom) {
                auto *rop = reinterpret_cast<UdpRecvOp *>(ov);
                if (ok && bytes > 0)
                    srv->onDatagram(rop->data, static_cast<int>(bytes), rop->fromAddr);
                // Re-arm this recv slot.
                if (srv->m_running.load())
                    srv->postRecvFrom(rop);

            }
            else {  // SendTo complete
                pool_release(srv->m_sendPool,
                    reinterpret_cast<SendReq *>(
                        reinterpret_cast<char *>(op) -
                        offsetof(SendReq, op)));
            }
        }
        return 0;
    }

    // ─────────────────────────────────────────────────────────────────────────────
    //  Timer thread (idle peer reaping)
    // ─────────────────────────────────────────────────────────────────────────────

    unsigned __stdcall IocpUdpServer::timerThread(void *arg)
    {
        auto *srv = static_cast<IocpUdpServer *>(arg);

        while (srv->m_running.load()) {
            Sleep(kIdleCheckMs);
            if (!srv->m_idleTimeoutMs) continue;

            std::uint64_t now = GetTickCount64();
            std::vector<UdpPeer *> timedOut;

            EnterCriticalSection(&srv->m_peerLock);
            for (UdpPeer *p = srv->m_peerHead; p;) {
                UdpPeer *nx = p->next;
                if (p->lastActive && (now - p->lastActive > srv->m_idleTimeoutMs)) {
                    srv->peerRemove(p);
                    timedOut.push_back(p);
                }
                p = nx;
            }
            LeaveCriticalSection(&srv->m_peerLock);

            for (UdpPeer *p : timedOut) {
                if (srv->m_cb.on_peer_timeout) srv->m_cb.on_peer_timeout(p);
                delete p;
            }
        }
        return 0;
    }

    // ─────────────────────────────────────────────────────────────────────────────
    //  lastError
    // ─────────────────────────────────────────────────────────────────────────────

    std::string IocpUdpServer::lastError() const noexcept
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