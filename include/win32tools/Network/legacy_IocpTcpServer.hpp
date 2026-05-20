#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <winsock2.h>
#include <windows.h>

#include <win32tools/Network/NetworkSocket.hpp>

namespace w32t {

/// @brief Per-connection I/O context overlay on top of OVERLAPPED.
///
/// Stored as the completion key so the worker thread can identify which
/// socket and operation triggered the completion notification.
struct IoContext : public OVERLAPPED {
    /// @brief Which async I/O operation is pending on this context.
    enum class State : std::uint8_t {
        IoAccept, ///< Waiting for a new connection.
        IoRecv,   ///< Waiting for inbound data.
        IoSend    ///< Waiting for outbound data to drain.
    };

    IoContext();
    ~IoContext();

    static constexpr std::size_t k_bufferSize = 4096;

    SOCKET   socketHandle;                ///< Associated client socket.
    State    ioState;                     ///< Current pending operation.
    WSABUF   wsaBuf;                      ///< Scatter/gather buffer descriptor.
    char     buffer[k_bufferSize];        ///< Underlying data buffer.
    ULONG    bytesToSend;                 ///< Bytes queued for send.
    ULONG    bytesSent;                   ///< Bytes already sent.
};

// ─────────────────────────────────────────────────────────────────────────────

/// @brief Asynchronous TCP server using I/O Completion Ports (IOCP).
///
/// Call Listen() once to bind and start accepting. Pass a worker-thread
/// function to Listen(); that thread receives completion notifications via
/// GetQueuedCompletionStatus(). Call Accept() in a loop to queue each new
/// incoming connection into the completion port.
///
/// ### Minimal usage
/// @code
///   DWORD WINAPI workerThread(LPVOID param) { ... }
///
///   w32t::IocpTcpServer server;
///   server.listen(8080, workerThread);
///   while (true) {
///       w32t::NetworkSocket dummy(w32t::Socket::Type::Tcp);
///       server.accept(dummy);
///   }
/// @endcode
class IocpTcpServer : public NetworkSocket {
public:
    IocpTcpServer();
    ~IocpTcpServer() override;

    // Non-copyable: owns OS-level IOCP handle and worker threads.
    IocpTcpServer(const IocpTcpServer&)            = delete;
    IocpTcpServer& operator=(const IocpTcpServer&) = delete;

    // ── Server lifecycle ─────────────────────────────────────────────────────

    /// @brief Bind to @p port, create the IOCP, and spawn worker threads
    ///        (one per logical CPU × 2).
    /// @param port          Local port to listen on.
    /// @param workerThread  Thread proc that calls GetQueuedCompletionStatus.
    /// @return true on success.
    bool listen(unsigned int port,
                LPTHREAD_START_ROUTINE workerThread);

    /// @brief Accept one incoming connection and associate it with the IOCP.
    ///
    /// Issues an initial WSARecv so the worker thread is notified on the
    /// first inbound data.
    ///
    /// @param placeholder  Unused parameter kept for API symmetry.
    /// @return true on success.
    bool accept(NetworkSocket& placeholder);

private:
    /// @brief Create the socket, IOCP, and worker threads.
    bool initialise(LPTHREAD_START_ROUTINE workerThread);

    /// @brief Associate @p socketHandle with the IOCP and return a new IoContext.
    IoContext* associateWithIocp(SOCKET socketHandle, IoContext::State state);

    IoContext* m_clientContext;  ///< Most recently accepted client context.
    bool       m_initialised;
    HANDLE     m_iocpHandle;     ///< I/O Completion Port kernel object.
};

} // namespace w32t
