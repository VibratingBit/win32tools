#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <winsock2.h>

#include <cstddef>
#include <string>

namespace w32t {

/// @brief RAII base class for a Winsock TCP or UDP socket.
///
/// Handles WSAStartup/WSACleanup, socket creation, and simple querying.
/// Derived classes add connection-oriented or server-oriented behaviour.
///
/// Error messages are accumulated in m_errorLog and may be retrieved via
/// lastError().
class Socket {
public:
    /// @brief Supported socket types.
    enum class Type : std::uint8_t {
        Tcp, ///< SOCK_STREAM / IPPROTO_TCP
        Udp  ///< SOCK_DGRAM  / IPPROTO_UDP
    };

    explicit Socket(Type type);
    virtual ~Socket();

    // Non-copyable: wraps an OS resource.
    Socket(const Socket&)            = delete;
    Socket& operator=(const Socket&) = delete;

    // ── Socket lifecycle ─────────────────────────────────────────────────────

    /// @brief Create the underlying socket file descriptor.
    /// @return true on success.
    virtual bool create();

    /// @brief Adopt an already-created socket handle (e.g. from accept()).
    void create(SOCKET handle);

    /// @brief Shutdown both directions of the socket.
    virtual void close();

    // ── Querying ─────────────────────────────────────────────────────────────

    /// @brief Return the underlying SOCKET handle.
    [[nodiscard]] SOCKET handle() const noexcept { return m_socket; }

    /// @brief Return the locally bound port number, or 0 on failure.
    [[nodiscard]] unsigned short localPort();

    /// @brief Return the locally bound IP address string, or an error message.
    [[nodiscard]] std::string localAddress();

    // ── Blocking mode ────────────────────────────────────────────────────────

    /// @brief Switch the socket between blocking and non-blocking mode.
    /// @param blocking  true = blocking, false = non-blocking.
    /// @return true on success.
    bool setBlocking(bool blocking);

    // ── Error reporting ──────────────────────────────────────────────────────

    /// @brief Return accumulated error messages.
    [[nodiscard]] std::string lastError() const { return m_errorLog; }

protected:
    void        appendError(const std::string& msg) { m_errorLog += msg; }
    void        trimError(std::size_t chars);

    Type        m_type;
    SOCKET      m_socket;
    std::string m_errorLog;

    // Keep old name available to derived classes that already use it.
    std::string& errorString { m_errorLog };
};

} // namespace w32t
