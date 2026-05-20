#ifndef W32T_SOCKET_HPP
#define W32T_SOCKET_HPP

// ─────────────────────────────────────────────────────────────────────────────
//  w32t :: Socket
//
//  Thin RAII wrapper around a Winsock SOCKET handle.
//  Owns exactly one handle; non-copyable, movable.
//  Provides type tagging (Tcp / Udp) and a few convenience helpers used by
//  the higher-level networking classes.
// ─────────────────────────────────────────────────────────────────────────────

#ifndef WIN32_LEAN_AND_MEAN
#  define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#  define NOMINMAX
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "Ws2_32.lib")

#include <cstdint>
#include <string>

namespace w32t {

// ── WSA lifetime guard ────────────────────────────────────────────────────────
// Call once per process before creating any sockets.
// Returns true on success; idempotent on repeated calls.
bool wsa_init() noexcept;
void wsa_cleanup() noexcept;

// ─────────────────────────────────────────────────────────────────────────────

class Socket {
public:
    enum class Type { Tcp, Udp };

    // Construct with an invalid handle; call create() or create(existing).
    explicit Socket(Type t = Type::Tcp) noexcept;

    // Wrap an already-accepted / already-connected OS handle.
    explicit Socket(Type t, SOCKET existing) noexcept;

    ~Socket() noexcept;

    // Non-copyable, movable.
    Socket(const Socket&)            = delete;
    Socket& operator=(const Socket&) = delete;
    Socket(Socket&&)                 noexcept;
    Socket& operator=(Socket&&)      noexcept;

    // ── Lifecycle ─────────────────────────────────────────────────────────────

    // Create and store a new OS socket of the configured type.
    // Returns true on success.
    bool create() noexcept;

    // Adopt an existing OS handle (closes the current one first).
    void create(SOCKET existing) noexcept;

    // Graceful shutdown then close.
    void close() noexcept;

    // ── Accessors ─────────────────────────────────────────────────────────────

    [[nodiscard]] SOCKET handle()  const noexcept { return m_sock; }
    [[nodiscard]] bool   valid()   const noexcept { return m_sock != INVALID_SOCKET; }
    [[nodiscard]] Type   type()    const noexcept { return m_type; }

    // ── Address helpers ───────────────────────────────────────────────────────

    [[nodiscard]] std::string localAddress()  const noexcept;
    [[nodiscard]] std::string peerAddress()   const noexcept;
    [[nodiscard]] uint16_t    localPort()     const noexcept;
    [[nodiscard]] uint16_t    peerPort()      const noexcept;
    [[nodiscard]] bool        isConnected()   const noexcept;

    // Last Winsock error as a string (calls FormatMessage).
    [[nodiscard]] std::string lastError() const noexcept;

    // Raw WSA error code from the last failed operation.
    [[nodiscard]] int lastErrorCode() const noexcept { return m_lastErr; }

protected:
    SOCKET m_sock    = INVALID_SOCKET;
    Type   m_type    = Type::Tcp;
    mutable int m_lastErr = 0;

private:
    static std::string addrToString(const sockaddr_storage& ss) noexcept;
    static uint16_t    addrToPort  (const sockaddr_storage& ss) noexcept;
    static bool        fillLocal   (SOCKET s, sockaddr_storage& out) noexcept;
    static bool        fillPeer    (SOCKET s, sockaddr_storage& out) noexcept;
};

} // namespace w32t

#endif // W32T_SOCKET_HPP