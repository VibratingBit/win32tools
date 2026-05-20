#ifndef W32T_IOCPTCPSERVER_HPP
#define W32T_IOCPTCPSERVER_HPP

// ─────────────────────────────────────────────────────────────────────────────
//  w32t :: IocpTcpServer
// ─────────────────────────────────────────────────────────────────────────────

#include <win32tools/Network/IocpBase.hpp>
#include <win32tools/Network/Socket.hpp>

#include <atomic>
#include <cstdint>
#include <functional>
#include <string>

namespace w32t {

    struct TcpClient;
    class  IocpTcpServer;
    using  TcpClientHandle = TcpClient *;

    // ── Callbacks ─────────────────────────────────────────────────────────────────

    struct TcpServerCallbacks {
        std::function<void(TcpClientHandle)>                    on_connect;
        std::function<void(TcpClientHandle, const char *, int)>  on_data;
        std::function<void(TcpClientHandle)>                    on_close;
    };

    // ── Per-client state ──────────────────────────────────────────────────────────

    struct TcpClient {
        SOCKET          sock;
        IocpTcpServer *server;

        int             id;
        int             isMuted;
        std::uint64_t   lastActive;

        char            ip[46];
        int             port;
        std::uint64_t   arrivalTs;

        NetProtocol     protocol;
        char            staging[kStagingSize];
        int             stagingLen;

        IocpOp          recvOp;
        WSABUF          recvWsa;
        char            recvData[kRecvBufSize];

        std::atomic<int> refs;
        std::atomic<int> closed;

        TcpClient *next;
        TcpClient *prev;

        TcpClient()
            : sock(INVALID_SOCKET)
            , server(nullptr)
            , id(0), isMuted(0), lastActive(0)
            , port(0), arrivalTs(0)
            , protocol(NetProtocol::Unknown)
            , stagingLen(0)
            , next(nullptr), prev(nullptr)
        {
            std::memset(ip, 0, sizeof(ip));
            std::memset(staging, 0, sizeof(staging));
            std::memset(&recvWsa, 0, sizeof(recvWsa));
            std::memset(recvData, 0, sizeof(recvData));
            refs.store(1);
            closed.store(0);
        }
    };

    // ─────────────────────────────────────────────────────────────────────────────

    class IocpTcpServer {
    public:
        IocpTcpServer();
        ~IocpTcpServer() noexcept;

        IocpTcpServer(const IocpTcpServer &) = delete;
        IocpTcpServer &operator=(const IocpTcpServer &) = delete;

        // ── Lifecycle ─────────────────────────────────────────────────────────────
        bool init(const TcpServerCallbacks &cb, int workerCount = 0) noexcept;

        // Blocking accept loop — call from a dedicated thread.
        // listen(port, LPTHREAD_START_ROUTINE) starts one worker
        // using the supplied function and returns immediately.
        bool listen(uint16_t port,
            LPTHREAD_START_ROUTINE legacyWorker = nullptr,
            const char *ip = "0.0.0.0") noexcept;

        void stop()     noexcept;
        void shutdown() noexcept;

        bool accept(Socket &outSock) noexcept;

        // ── Per-client ────────────────────────────────────────────────────────────
        int  send(TcpClientHandle c, const void *data, int len) noexcept;
        void close(TcpClientHandle c)                            noexcept;

        // ── Broadcast ─────────────────────────────────────────────────────────────
        void broadcast(const void *data, int len)                          noexcept;
        void broadcastExcept(TcpClientHandle exclude, const void *data, int len) noexcept;

        // ── Registry ──────────────────────────────────────────────────────────────
        int             clientCount()    const noexcept;
        TcpClientHandle findById(int id) const noexcept;

        using IterateCb = std::function<void(TcpClientHandle)>;
        // WARNING: do NOT call close() from inside the callback — deadlock risk.
        void iterateClients(const IterateCb &cb) noexcept;

        // ── Diagnostics ───────────────────────────────────────────────────────────
        [[nodiscard]] std::string localAddress() const noexcept;
        [[nodiscard]] uint16_t    localPort()    const noexcept;
        [[nodiscard]] std::string lastError()    const noexcept;

    private:
        static unsigned __stdcall workerThread(void *arg);
        static unsigned __stdcall timerThread(void *arg);

        void       closeInternal(TcpClient *c) noexcept;
        bool       postRecv(TcpClient *c) noexcept;
        void       processStaging(TcpClient *c) noexcept;
        TcpClient *createClient(SOCKET s)     noexcept;

        void registryAdd(TcpClient *c) noexcept;
        void registryRemove(TcpClient *c) noexcept;

        static void acquire(TcpClient *c) noexcept;
        static void release(TcpClient *c) noexcept;

        HANDLE              m_iocp = nullptr;
        HANDLE *m_workers = nullptr;
        int                 m_workerCount = 0;
        HANDLE              m_timerThread = nullptr;
        SOCKET              m_listenSock = INVALID_SOCKET;

        std::atomic<int>    m_running;
        std::atomic<int>    m_clientCount;

        mutable CRITICAL_SECTION m_regLock;
        TcpClient *m_head = nullptr;

        SLIST_HEADER        m_pool;
        TcpServerCallbacks  m_cb;

        mutable int         m_lastErr = 0;
        uint16_t            m_boundPort = 0;
        std::string         m_boundIp;
    };

} // namespace w32t

#endif // W32T_IOCPTCPSERVER_HPP