#ifndef W32T_IOCPUDPSERVER_HPP
#define W32T_IOCPUDPSERVER_HPP

// ─────────────────────────────────────────────────────────────────────────────
//  w32t :: IocpUdpServer
// ─────────────────────────────────────────────────────────────────────────────

#include <win32tools/Network/IocpBase.hpp>

#include <atomic>
#include <cstdint>
#include <functional>
#include <string>
#include <vector>

namespace w32t {

    // ── Forward declaration so UdpRecvOp can hold a pointer ──────────────────────
    class IocpUdpServer;

    // ── Per-peer record ───────────────────────────────────────────────────────────

    struct UdpPeer {
        sockaddr_storage addr;
        char             ip[46];
        int              port;
        int              id;
        std::uint64_t    lastActive;

        UdpPeer *next;
        UdpPeer *prev;

        UdpPeer()
            : port(0), id(0), lastActive(0), next(nullptr), prev(nullptr)
        {
            std::memset(&addr, 0, sizeof(addr));
            std::memset(ip, 0, sizeof(ip));
        }
    };

    // ── Callbacks ─────────────────────────────────────────────────────────────────

    struct UdpServerCallbacks {
        std::function<void(UdpPeer *, const char *, int)> on_data;
        std::function<void(UdpPeer *)>                   on_new_peer;
        std::function<void(UdpPeer *)>                   on_peer_timeout;
    };

    // ── Per-recv overlapped ───────────────────────────────────────────────────────
    // UdpRecvOp is defined AFTER IocpUdpServer is forward-declared so that the
    // 'server' pointer member is well-formed (pointer to incomplete type is OK).

    struct UdpRecvOp {
        OVERLAPPED       ov;            // MUST stay first
        IocpOpType       type;
        WSABUF           wsa;
        sockaddr_storage fromAddr;
        INT              fromLen;
        char             data[kRecvBufSize];
        IocpUdpServer *server;        // back-pointer (incomplete type is fine for ptr)

        UdpRecvOp()
            : type(IocpOpType::RecvFrom)
            , fromLen(static_cast<INT>(sizeof(sockaddr_storage)))
            , server(nullptr)
        {
            std::memset(&ov, 0, sizeof(ov));
            std::memset(&wsa, 0, sizeof(wsa));
            std::memset(&fromAddr, 0, sizeof(fromAddr));
            std::memset(data, 0, sizeof(data));
        }
    };

    // ─────────────────────────────────────────────────────────────────────────────

    class IocpUdpServer {
    public:
        explicit IocpUdpServer(int concurrentRecvs = 4);
        ~IocpUdpServer() noexcept;

        IocpUdpServer(const IocpUdpServer &) = delete;
        IocpUdpServer &operator=(const IocpUdpServer &) = delete;

        // ── Lifecycle ─────────────────────────────────────────────────────────────
        bool init(const UdpServerCallbacks &cb, int workerCount = 0) noexcept;
        bool listen(uint16_t port, const char *ip = "0.0.0.0")       noexcept;
        void stop()     noexcept;
        void shutdown() noexcept;

        // ── Send ──────────────────────────────────────────────────────────────────
        int  sendTo(const sockaddr_storage &dest, const void *data, int len) noexcept;
        int  sendTo(UdpPeer *peer, const void *data, int len) noexcept;
        void broadcast(const void *data, int len)                            noexcept;

        // ── Peer registry ─────────────────────────────────────────────────────────
        int      peerCount()                   const noexcept { return m_peerCount.load(); }
        UdpPeer *findPeer(const char *ip, int port) const noexcept;
        UdpPeer *findPeerById(int id)               const noexcept;

        using IteratePeerCb = std::function<void(UdpPeer *)>;
        void iteratePeers(const IteratePeerCb &cb) noexcept;

        void setIdleTimeout(DWORD ms) noexcept { m_idleTimeoutMs = ms; }

        // ── Diagnostics ───────────────────────────────────────────────────────────
        [[nodiscard]] std::string lastError() const noexcept;
        [[nodiscard]] uint16_t    boundPort() const noexcept { return m_boundPort; }

    private:
        static unsigned __stdcall workerThread(void *arg);
        static unsigned __stdcall timerThread(void *arg);

        bool     postRecvFrom(UdpRecvOp *op)                          noexcept;
        void     onDatagram(const char *data, int len,
            const sockaddr_storage &from)             noexcept;
        UdpPeer *peerFind(const sockaddr_storage &addr)      noexcept;
        UdpPeer *peerGetOrCreate(const sockaddr_storage &addr)      noexcept;
        void     peerAdd(UdpPeer *p)                        noexcept;
        void     peerRemove(UdpPeer *p)                        noexcept;

        SOCKET              m_sock = INVALID_SOCKET;
        HANDLE              m_iocp = nullptr;
        HANDLE *m_workers = nullptr;
        int                 m_workerCount = 0;
        HANDLE              m_timerThread = nullptr;

        std::atomic<int>    m_running;
        std::atomic<int>    m_peerCount;

        mutable CRITICAL_SECTION m_peerLock;
        UdpPeer *m_peerHead = nullptr;
        std::atomic<int>    m_nextId;

        SLIST_HEADER        m_sendPool;

        int                 m_concurrentRecvs = 4;
        UdpRecvOp *m_recvOps = nullptr;

        UdpServerCallbacks  m_cb;
        DWORD               m_idleTimeoutMs = 0;
        uint16_t            m_boundPort = 0;
        mutable int         m_lastErr = 0;
    };

} // namespace w32t

#endif // W32T_IOCPUDPSERVER_HPP