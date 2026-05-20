#ifndef W32T_NETWORKSOCKET_HPP
#define W32T_NETWORKSOCKET_HPP

// ─────────────────────────────────────────────────────────────────────────────
//  w32t :: NetworkSocket
//
//  Synchronous TCP/UDP socket with Packet framing.
//  Wraps Socket and adds connect / send(Packet) / recv(Packet).
//
//  TCP send:  4-byte LE length prefix + payload.
//  TCP recv:  reads the 4-byte header then the payload in full.
//  UDP:       sendto / recvfrom with no framing; caller manages datagrams.
// ─────────────────────────────────────────────────────────────────────────────

#include <win32tools/Network/Socket.hpp>
#include <win32tools/Network/Packet.hpp>

#include <string>
#include <cstdint>

namespace w32t {

class NetworkSocket : public Socket {
public:
    explicit NetworkSocket(Type t = Type::Tcp) noexcept;

    // Wrap an existing OS handle (used by IocpTcpServer::accept shim).
    explicit NetworkSocket(Type t, SOCKET existing) noexcept;

    // ── Client connect ────────────────────────────────────────────────────────
    bool connectTo(const std::string& ip, uint16_t port) noexcept;

    // ── Packet I/O (TCP) ──────────────────────────────────────────────────────

    // Send: prepend 4-byte LE length then blocking send of full payload.
    // Returns bytes sent (including header) or -1 on error.
    int send(const Packet& pkt) noexcept;

    // Recv: read 4-byte header, then payload.  Fills pkt (clears first).
    // Returns payload bytes read, 0 on graceful close, -1 on error.
    int recv(Packet& pkt) noexcept;

    // ── Raw I/O (UDP / low-level) ─────────────────────────────────────────────
    int sendRaw(const void* data, int len) noexcept;
    int recvRaw(void* buf,  int len) noexcept;

    // ── UDP peer (optional; used for connected UDP) ───────────────────────────
    bool setUdpPeer(const std::string& ip, uint16_t port) noexcept;
};

} // namespace w32t

#endif // W32T_NETWORKSOCKET_HPP