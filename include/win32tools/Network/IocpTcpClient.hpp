#ifndef W32T_IOCPTCPCLIENT_HPP
#define W32T_IOCPTCPCLIENT_HPP

// ─────────────────────────────────────────────────────────────────────────────
//  w32t :: IocpTcpClient
//
//  Async IOCP TCP client with the same protocol framing as IocpTcpServer.
//
//  Connects to a remote server; all I/O is async via a private IOCP + one
//  worker thread.  Callbacks fire on that thread — keep them short.
//
//  Protocol auto-detected from the FIRST byte received from the server:
//    Packet : binary  — 4-byte LE length prefix
//    Telnet : text    — newline-delimited
//
//  Thread safety
//    send()        — safe from any thread
//    disconnect()  — safe from any thread; idempotent
//    callbacks     — fired on the internal worker thread only
// ─────────────────────────────────────────────────────────────────────────────

#include <win32tools/Network/IocpBase.hpp>

#include <atomic>
#include <cstdint>
#include <functional>
#include <string>

namespace w32t {

struct TcpClientCallbacks {
    std::function<void()>                             on_connect;
    std::function<void(const char* data, int len)>    on_data;
    std::function<void()>                             on_close;
};

class IocpTcpClient {
public:
    IocpTcpClient();
    ~IocpTcpClient() noexcept;

    IocpTcpClient(const IocpTcpClient&)            = delete;
    IocpTcpClient& operator=(const IocpTcpClient&) = delete;

    // ── Connect ───────────────────────────────────────────────────────────────
    // Synchronously connects, then arms the async recv loop.
    // Returns false on failure; check lastError().
    bool connect(const std::string& ip, uint16_t port,
                 const TcpClientCallbacks& cb) noexcept;

    // ── Send ──────────────────────────────────────────────────────────────────
    // PACKET mode: 4-byte LE length prepended automatically.
    // TELNET mode: bare '\n' normalised to '\r\n'.
    // Returns 0 on success, -1 on failure.
    int send(const void* data, int len) noexcept;

    // ── Disconnect ────────────────────────────────────────────────────────────
    void disconnect() noexcept;

    // ── State ─────────────────────────────────────────────────────────────────
    [[nodiscard]] bool        connected()   const noexcept { return m_connected.load(); }
    [[nodiscard]] std::string remoteIp()    const noexcept { return m_remoteIp;  }
    [[nodiscard]] uint16_t    remotePort()  const noexcept { return m_remotePort; }
    [[nodiscard]] std::string lastError()   const noexcept;

private:
    static unsigned __stdcall workerThread(void* arg);

    bool postRecv()          noexcept;
    void processStaging()    noexcept;
    void closeInternal()     noexcept;

    SOCKET              m_sock        = INVALID_SOCKET;
    HANDLE              m_iocp        = nullptr;
    HANDLE              m_worker      = nullptr;

    NetProtocol         m_protocol    = NetProtocol::Unknown;
    char                m_staging[kStagingSize]{};
    int                 m_stagingLen  = 0;

    IocpOp              m_recvOp{};
    WSABUF              m_recvWsa{};
    char                m_recvData[kRecvBufSize]{};

    SLIST_HEADER        m_pool{};

    TcpClientCallbacks  m_cb{};

    std::atomic<int>    m_running{ 0 };
    std::atomic<int>    m_connected{ 0 };
    std::atomic<int>    m_closed{ 0 };

    std::string         m_remoteIp;
    uint16_t            m_remotePort  = 0;
    mutable int         m_lastErr     = 0;
};

} // namespace w32t

#endif // W32T_IOCPTCPCLIENT_HPP