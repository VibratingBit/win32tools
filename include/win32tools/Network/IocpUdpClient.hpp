#ifndef W32T_IOCPUDPCLIENT_HPP
#define W32T_IOCPUDPCLIENT_HPP

// ─────────────────────────────────────────────────────────────────────────────
//  w32t :: IocpUdpClient
// ─────────────────────────────────────────────────────────────────────────────

#include <win32tools/Network/IocpBase.hpp>

#include <atomic>
#include <cstdint>
#include <functional>
#include <string>

namespace w32t {

    struct UdpClientCallbacks {
        std::function<void(const sockaddr_storage &from,
            const char *data, int len)> on_data;
        std::function<void()>                          on_close;
    };

    // Per-outstanding recv operation.
    struct UdpClientRecvOp {
        OVERLAPPED       ov;            // MUST stay first
        IocpOpType       type;
        WSABUF           wsa;
        sockaddr_storage fromAddr;
        INT              fromLen;
        char             data[kRecvBufSize];

        UdpClientRecvOp()
            : type(IocpOpType::RecvFrom)
            , fromLen(static_cast<INT>(sizeof(sockaddr_storage)))
        {
            std::memset(&ov, 0, sizeof(ov));
            std::memset(&wsa, 0, sizeof(wsa));
            std::memset(&fromAddr, 0, sizeof(fromAddr));
            std::memset(data, 0, sizeof(data));
        }
    };

    class IocpUdpClient {
    public:
        explicit IocpUdpClient(int concurrentRecvs = 2);
        ~IocpUdpClient() noexcept;

        IocpUdpClient(const IocpUdpClient &) = delete;
        IocpUdpClient &operator=(const IocpUdpClient &) = delete;

        // ── Connected mode ────────────────────────────────────────────────────────
        bool connectTo(const std::string &serverIp, uint16_t serverPort,
            const UdpClientCallbacks &cb,
            uint16_t localPort = 0) noexcept;

        // ── Unconnected mode ──────────────────────────────────────────────────────
        bool bind(uint16_t localPort, const UdpClientCallbacks &cb) noexcept;

        // ── Send ──────────────────────────────────────────────────────────────────
        int send(const void *data, int len)                       noexcept;
        int sendTo(const sockaddr_storage &dest,
            const void *data, int len)                       noexcept;

        // ── Disconnect ────────────────────────────────────────────────────────────
        void disconnect() noexcept;

        // ── State ─────────────────────────────────────────────────────────────────
        [[nodiscard]] bool        active()    const noexcept { return m_active.load() != 0; }
        [[nodiscard]] uint16_t    localPort() const noexcept { return m_localPort; }
        [[nodiscard]] std::string lastError() const noexcept;

    private:
        static unsigned __stdcall workerThread(void *arg);

        bool initIocp()                        noexcept;
        bool postRecvFrom(UdpClientRecvOp *op) noexcept;
        void closeInternal()                   noexcept;

        SOCKET              m_sock = INVALID_SOCKET;
        HANDLE              m_iocp = nullptr;
        HANDLE              m_worker = nullptr;

        bool                m_connected = false;

        int                 m_concurrentRecvs = 2;
        UdpClientRecvOp *m_recvOps = nullptr;

        SLIST_HEADER        m_sendPool;

        UdpClientCallbacks  m_cb;

        std::atomic<int>    m_running;
        std::atomic<int>    m_active;
        std::atomic<int>    m_closed;

        uint16_t            m_localPort = 0;
        mutable int         m_lastErr = 0;
    };

} // namespace w32t

#endif // W32T_IOCPUDPCLIENT_HPP