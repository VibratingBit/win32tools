#include <win32tools/Network/Socket.hpp>

#include <string>
#include <cstring>

namespace w32t {

// ── WSA lifetime ──────────────────────────────────────────────────────────────

bool wsa_init() noexcept
{
    WSADATA wd{};
    return WSAStartup(MAKEWORD(2, 2), &wd) == 0;
}

void wsa_cleanup() noexcept
{
    WSACleanup();
}

// ── Socket ────────────────────────────────────────────────────────────────────

Socket::Socket(Type t) noexcept
    : m_type(t) {}

Socket::Socket(Type t, SOCKET existing) noexcept
    : m_sock(existing), m_type(t) {}

Socket::~Socket() noexcept { close(); }

Socket::Socket(Socket&& o) noexcept
    : m_sock(o.m_sock), m_type(o.m_type), m_lastErr(o.m_lastErr)
{
    o.m_sock = INVALID_SOCKET;
}

Socket& Socket::operator=(Socket&& o) noexcept
{
    if (this != &o) {
        close();
        m_sock    = o.m_sock;
        m_type    = o.m_type;
        m_lastErr = o.m_lastErr;
        o.m_sock  = INVALID_SOCKET;
    }
    return *this;
}

bool Socket::create() noexcept
{
    close();
    int sockType = (m_type == Type::Tcp) ? SOCK_STREAM : SOCK_DGRAM;
    int proto    = (m_type == Type::Tcp) ? IPPROTO_TCP : IPPROTO_UDP;
    m_sock = WSASocketW(AF_INET, sockType, proto,
                        nullptr, 0, WSA_FLAG_OVERLAPPED);
    if (m_sock == INVALID_SOCKET) {
        m_lastErr = WSAGetLastError();
        return false;
    }
    return true;
}

void Socket::create(SOCKET existing) noexcept
{
    close();
    m_sock = existing;
}

void Socket::close() noexcept
{
    if (m_sock != INVALID_SOCKET) {
        shutdown(m_sock, SD_BOTH);
        closesocket(m_sock);
        m_sock = INVALID_SOCKET;
    }
}

// ── Address helpers ───────────────────────────────────────────────────────────

bool Socket::fillLocal(SOCKET s, sockaddr_storage& out) noexcept
{
    std::memset(&out, 0, sizeof(out));
    int len = sizeof(out);
    return getsockname(s, reinterpret_cast<sockaddr*>(&out), &len) == 0;
}

bool Socket::fillPeer(SOCKET s, sockaddr_storage& out) noexcept
{
    std::memset(&out, 0, sizeof(out));
    int len = sizeof(out);
    return getpeername(s, reinterpret_cast<sockaddr*>(&out), &len) == 0;
}

std::string Socket::addrToString(const sockaddr_storage& ss) noexcept
{
    char buf[INET6_ADDRSTRLEN] = {};
    if (ss.ss_family == AF_INET) {
        inet_ntop(AF_INET,
            &reinterpret_cast<const sockaddr_in*>(&ss)->sin_addr,
            buf, sizeof(buf));
    } else if (ss.ss_family == AF_INET6) {
        inet_ntop(AF_INET6,
            &reinterpret_cast<const sockaddr_in6*>(&ss)->sin6_addr,
            buf, sizeof(buf));
    }
    return buf;
}

uint16_t Socket::addrToPort(const sockaddr_storage& ss) noexcept
{
    if (ss.ss_family == AF_INET)
        return ntohs(reinterpret_cast<const sockaddr_in*>(&ss)->sin_port);
    if (ss.ss_family == AF_INET6)
        return ntohs(reinterpret_cast<const sockaddr_in6*>(&ss)->sin6_port);
    return 0;
}

std::string Socket::localAddress() const noexcept
{
    sockaddr_storage ss{};
    return fillLocal(m_sock, ss) ? addrToString(ss) : std::string{};
}

std::string Socket::peerAddress() const noexcept
{
    sockaddr_storage ss{};
    return fillPeer(m_sock, ss) ? addrToString(ss) : std::string{};
}

uint16_t Socket::localPort() const noexcept
{
    sockaddr_storage ss{};
    return fillLocal(m_sock, ss) ? addrToPort(ss) : 0;
}

uint16_t Socket::peerPort() const noexcept
{
    sockaddr_storage ss{};
    return fillPeer(m_sock, ss) ? addrToPort(ss) : 0;
}

bool Socket::isConnected() const noexcept
{
    if (m_sock == INVALID_SOCKET) return false;
    sockaddr_storage ss{};
    return fillPeer(m_sock, ss);
}

std::string Socket::lastError() const noexcept
{
    if (m_lastErr == 0) return {};
    char buf[512]{};
    FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                   nullptr, static_cast<DWORD>(m_lastErr), 0,
                   buf, static_cast<DWORD>(sizeof(buf)), nullptr);
    // Strip trailing \r\n
    for (int i = static_cast<int>(strlen(buf)) - 1;
         i >= 0 && (buf[i] == '\r' || buf[i] == '\n'); --i)
        buf[i] = '\0';
    return buf;
}

} // namespace w32t