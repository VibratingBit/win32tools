#include <win32tools/Network/Socket.hpp>

#include <ws2tcpip.h>

namespace w32t {

Socket::Socket(Type type)
    : m_type(type)
    , m_socket(INVALID_SOCKET)
    , m_errorLog{}
{
    WSADATA wsa{};
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        m_errorLog += "WSAStartup failed.\n";
        WSACleanup();
    }
}

Socket::~Socket()
{
    if (m_socket != INVALID_SOCKET) {
        closesocket(m_socket);
        m_socket = INVALID_SOCKET;
    }
    WSACleanup();
}

// ── Lifecycle ─────────────────────────────────────────────────────────────────

bool Socket::create()
{
    if (m_type == Type::Tcp) {
        m_socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (m_socket == INVALID_SOCKET) {
            m_errorLog += "Failed to create TCP socket.\n";
            return false;
        }
    } else {
        m_socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if (m_socket == INVALID_SOCKET) {
            m_errorLog += "Failed to create UDP socket.\n";
            return false;
        }
    }
    return true;
}

void Socket::create(SOCKET handle)
{
    m_socket = handle;
}

void Socket::close()
{
    shutdown(m_socket, SD_BOTH);
}

// ── Querying ──────────────────────────────────────────────────────────────────

unsigned short Socket::localPort()
{
    sockaddr_in addr{};
    int len = sizeof(addr);

    if (getsockname(m_socket, reinterpret_cast<sockaddr*>(&addr), &len) < 0) {
        m_errorLog += "getsockname failed (port).\n";
        return 0;
    }
    return ntohs(addr.sin_port);
}

std::string Socket::localAddress()
{
    sockaddr_in addr{};
    int len = sizeof(addr);

    if (getsockname(m_socket, reinterpret_cast<sockaddr*>(&addr), &len) < 0) {
        m_errorLog += "getsockname failed (address).\n";
        return m_errorLog;
    }
    char peerAddress[INET_ADDRSTRLEN]; // Buffer to hold the string
    InetNtop(AF_INET, &addr.sin_addr, peerAddress, INET_ADDRSTRLEN);

    return peerAddress;
}

// ── Blocking mode ─────────────────────────────────────────────────────────────

bool Socket::setBlocking(bool blocking)
{
    u_long mode = blocking ? 0u : 1u;
    return ioctlsocket(m_socket, FIONBIO, &mode) == 0;
}

// ── Error helpers ─────────────────────────────────────────────────────────────

void Socket::trimError(std::size_t chars)
{
    if (chars >= m_errorLog.size())
        m_errorLog.clear();
    else
        m_errorLog.erase(m_errorLog.size() - chars);
}

} // namespace w32t
