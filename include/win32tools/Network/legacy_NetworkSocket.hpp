#pragma once

#include <win32tools/Network/Socket.hpp>
#include <win32tools/Network/Packet.hpp>

#include <string>

namespace w32t {

/// @brief Connected-socket layer built on top of Socket.
///
/// Adds peer information (address / port), a blocking send loop, a
/// framing-aware receive method that uses the uint16 length prefix from
/// Packet, and a connect() helper for client-side use.
class NetworkSocket : public Socket {
public:
    explicit NetworkSocket(Type type);
    ~NetworkSocket() override;

    // ── Client-side connection ────────────────────────────────────────────────

    /// @brief Connect to a remote TCP endpoint.
    /// @param remoteAddress  Hostname or dotted-decimal IP.
    /// @param remotePort     Port number (host byte order).
    /// @return true on success.
    bool connectTo(const std::string& remoteAddress,
                   unsigned short     remotePort);

    // ── Send ─────────────────────────────────────────────────────────────────

    /// @brief Send raw bytes, looping until all @p dataSize bytes are sent.
    /// @return Total bytes sent, or SOCKET_ERROR on failure.
    int send(const void* data, std::size_t dataSize);

    /// @brief Send the contents of a Packet.
    /// @return Total bytes sent, or 0 if the packet is empty.
    int send(Packet& packet);

    // ── Receive ──────────────────────────────────────────────────────────────

    /// @brief Receive raw bytes into @p data.
    /// @return Bytes received (may be 0 or negative on error / disconnect).
    int recv(void* data, std::size_t dataSize);

    /// @brief Receive into a Packet, honouring the uint16 length prefix.
    ///
    /// Reads until at least (prefix + payload) bytes are available.
    /// @return Total bytes received on first read.
    int recv(Packet& packet);

    // ── Peer info ─────────────────────────────────────────────────────────────

    [[nodiscard]] unsigned short peerPort()    const noexcept;
    [[nodiscard]] std::string    peerAddress() const;
    [[nodiscard]] bool           isConnected() const noexcept { return m_connected; }

    // ── Overrides ────────────────────────────────────────────────────────────

    void close() override;

protected:
    SOCKET      m_peerSocket;
    std::string m_peerAddress;
    unsigned short m_peerPort;
    bool        m_connected;
};

} // namespace w32t
