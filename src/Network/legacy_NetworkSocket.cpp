#include <win32tools/Network/NetworkSocket.hpp>

#include <cstring>
#include <memory>

#include <ws2tcpip.h>

namespace w32t {

NetworkSocket::NetworkSocket(Type type)
    : Socket(type)
    , m_peerSocket(INVALID_SOCKET)
    , m_peerAddress{}
    , m_peerPort(0)
    , m_connected(false)
{}

NetworkSocket::~NetworkSocket() = default;

// ── Client connection ─────────────────────────────────────────────────────────

bool NetworkSocket::connectTo(const std::string &remoteAddress, unsigned short remotePort) {
    trimError(m_errorLog.size()); // Clear previous errors

    // 1. Resolve the hostname/IP address
    struct addrinfo hints = {}, *result = nullptr;
    hints.ai_family = AF_UNSPEC;     // Support both IPv4 and IPv6
    hints.ai_socktype = SOCK_STREAM; // TCP
    hints.ai_protocol = IPPROTO_TCP;

    std::string portStr = std::to_string(remotePort);
    int status = getaddrinfo(remoteAddress.c_str(), portStr.c_str(), &hints, &result);

    if (status != 0) {
        m_errorLog += "DNS Resolution failed: " + std::string(gai_strerror(status)) + "\n";
        return false;
    }

    // Ensure the result list is cleaned up when we leave this scope
    auto deleter = [](addrinfo* ptr) { if (ptr) freeaddrinfo(ptr); };
    std::unique_ptr<addrinfo, decltype(deleter)> addrPtr(result, deleter);
    //std::unique_ptr<addrinfo, void(*)(addrinfo *)> addrPtr(result, freeaddrinfo);

    bool success = false;
    // 2. Iterate through the list of addresses returned by DNS
    for (struct addrinfo *ptr = result; ptr != nullptr; ptr = ptr->ai_next) {

        // Re-create the socket based on the specific address family (IPv4 or IPv6)
        // If your base class already created a socket, you may need to close it if the family differs
        if (m_socket != INVALID_SOCKET) {
            close();
        }

        m_socket = socket(ptr->ai_family, ptr->ai_socktype, ptr->ai_protocol);
        if (m_socket == INVALID_SOCKET) continue;

        // 3. Attempt connection
        if (::connect(m_socket, ptr->ai_addr, static_cast<int>(ptr->ai_addrlen)) != SOCKET_ERROR) {
            success = true;

            // Store peer info
            char hostBuffer[NI_MAXHOST];
            if (getnameinfo(ptr->ai_addr, static_cast<socklen_t>(ptr->ai_addrlen),
                hostBuffer, sizeof(hostBuffer), nullptr, 0, NI_NUMERICHOST) == 0) {
                m_peerAddress = hostBuffer;
            }
            m_peerPort = remotePort;
            break;
        }
    }

    if (!success) {
        m_errorLog += "Connection failed: Unable to connect to any resolved address.\n";
        m_connected = false;
        return false;
    }

    m_connected = true;
    return true;
}
/*
bool NetworkSocket::connectTo(const std::string& remoteAddress,
                               unsigned short     remotePort)
{
    trimError(m_errorLog.size()); // clear previous errors

    if (!create()) {
        m_errorLog += "Failed to create socket for connection.\n";
        return false;
    }

    hostent* host = gethostbyname(remoteAddress.c_str());
    if (!host) {
        m_errorLog += "Failed to resolve hostname.\n";
        return false;
    }

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port   = htons(remotePort);
    addr.sin_addr.s_addr = *reinterpret_cast<unsigned long*>(host->h_addr_list[0]);

    if (::connect(m_socket, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) {
        m_errorLog += "Failed to connect.\n";
        m_connected = false;
        return false;
    }

    m_peerSocket  = m_socket;
    m_peerAddress = inet_ntoa(addr.sin_addr);
    m_peerPort    = ntohs(addr.sin_port);
    m_connected   = true;
    return true;
}
*/
// ── Send ──────────────────────────────────────────────────────────────────────

int NetworkSocket::send(const void* data, std::size_t dataSize)
{
    int totalSent = 0;
    while (static_cast<std::size_t>(totalSent) < dataSize) {
        int sent = ::send(m_socket,
                          static_cast<const char*>(data) + totalSent,
                          static_cast<int>(dataSize - totalSent),
                          0);
        if (sent == SOCKET_ERROR) {
            m_errorLog += "send() failed.\n";
            break;
        }
        totalSent += sent;
    }
    return totalSent;
}

int NetworkSocket::send(Packet& packet)
{
    if (packet.buffer.empty())
        return 0;
    return send(packet.buffer.data(), packet.buffer.size());
}

// ── Receive ───────────────────────────────────────────────────────────────────

int NetworkSocket::recv(void* data, std::size_t dataSize)
{
    return ::recv(m_socket,
                  static_cast<char*>(data),
                  static_cast<int>(dataSize),
                  0);
}

int NetworkSocket::recv(Packet& packet)
{
    packet.buffer.resize(8000);
    int received = recv(packet.buffer.data(), packet.buffer.size());

    if (received <= 0)
        return received;

    // Read the framing length prefix and loop until we have the full payload.
    const std::uint16_t frameSize =
        readUint16LE(&packet.buffer[packet.pos]);

    while (static_cast<std::size_t>(received) - sizeof(std::uint16_t) < frameSize) {
        received = recv(packet.buffer.data(), packet.buffer.size());
        if (received <= 0)
            break;
    }

    return received;
}

// ── Peer info ─────────────────────────────────────────────────────────────────

unsigned short NetworkSocket::peerPort() const noexcept
{
    return m_connected ? m_peerPort : 0;
}

std::string NetworkSocket::peerAddress() const
{
    return m_connected ? m_peerAddress : "Not connected";
}

// ── Overrides ─────────────────────────────────────────────────────────────────

void NetworkSocket::close()
{
    ::shutdown(m_peerSocket, SD_BOTH);
    Socket::close();
}

} // namespace w32t
