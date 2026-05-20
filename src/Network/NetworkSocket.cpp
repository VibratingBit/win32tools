#include <win32tools/Network/NetworkSocket.hpp>
#include <cstring>

namespace w32t {

NetworkSocket::NetworkSocket(Type t) noexcept
    : Socket(t) {}

NetworkSocket::NetworkSocket(Type t, SOCKET existing) noexcept
    : Socket(t, existing) {}

bool NetworkSocket::connectTo(const std::string& ip, uint16_t port) noexcept
{
    if (!valid()) {
        if (!create()) return false;
    }
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port   = htons(port);
    if (inet_pton(AF_INET, ip.c_str(), &addr.sin_addr) != 1) {
        m_lastErr = WSAGetLastError();
        return false;
    }
    if (::connect(m_sock,
                  reinterpret_cast<const sockaddr*>(&addr),
                  sizeof(addr)) == SOCKET_ERROR) {
        m_lastErr = WSAGetLastError();
        return false;
    }
    return true;
}

int NetworkSocket::send(const Packet& pkt) noexcept
{
    if (!valid()) return -1;

    std::uint32_t payloadLen = static_cast<std::uint32_t>(pkt.size());
    // Send 4-byte LE length header.
    if (::send(m_sock, reinterpret_cast<const char*>(&payloadLen),
               static_cast<int>(sizeof(payloadLen)), 0) == SOCKET_ERROR) {
        m_lastErr = WSAGetLastError();
        return -1;
    }
    if (payloadLen == 0) return static_cast<int>(sizeof(payloadLen));

    int sent = ::send(m_sock,
                      reinterpret_cast<const char*>(pkt.data()),
                      static_cast<int>(payloadLen), 0);
    if (sent == SOCKET_ERROR) {
        m_lastErr = WSAGetLastError();
        return -1;
    }
    return sent + static_cast<int>(sizeof(payloadLen));
}

int NetworkSocket::recv(Packet& pkt) noexcept
{
    pkt.clear();
    if (!valid()) return -1;

    // Read 4-byte header.
    std::uint32_t payloadLen = 0;
    int headerRecv = ::recv(m_sock,
                            reinterpret_cast<char*>(&payloadLen),
                            static_cast<int>(sizeof(payloadLen)),
                            MSG_WAITALL);
    if (headerRecv == 0)   return 0;   // graceful close
    if (headerRecv < 0) {
        m_lastErr = WSAGetLastError();
        return -1;
    }
    if (payloadLen == 0) return 0;

    pkt.resize(payloadLen);
    int totalRead = 0;
    while (static_cast<std::uint32_t>(totalRead) < payloadLen) {
        int n = ::recv(m_sock,
                       reinterpret_cast<char*>(pkt.data()) + totalRead,
                       static_cast<int>(payloadLen) - totalRead,
                       0);
        if (n <= 0) {
            if (n < 0) m_lastErr = WSAGetLastError();
            return n;
        }
        totalRead += n;
    }
    return totalRead;
}

int NetworkSocket::sendRaw(const void* data, int len) noexcept
{
    if (!valid() || !data || len <= 0) return -1;
    int r = ::send(m_sock, static_cast<const char*>(data), len, 0);
    if (r == SOCKET_ERROR) { m_lastErr = WSAGetLastError(); return -1; }
    return r;
}

int NetworkSocket::recvRaw(void* buf, int len) noexcept
{
    if (!valid() || !buf || len <= 0) return -1;
    int r = ::recv(m_sock, static_cast<char*>(buf), len, 0);
    if (r == SOCKET_ERROR) { m_lastErr = WSAGetLastError(); return -1; }
    return r;
}

bool NetworkSocket::setUdpPeer(const std::string& ip, uint16_t port) noexcept
{
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port   = htons(port);
    if (inet_pton(AF_INET, ip.c_str(), &addr.sin_addr) != 1) return false;
    return ::connect(m_sock,
                     reinterpret_cast<const sockaddr*>(&addr),
                     sizeof(addr)) != SOCKET_ERROR;
}

} // namespace w32t