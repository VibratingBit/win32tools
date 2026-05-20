#include <win32tools/Network/Packet.hpp>

#include <cstring>
#include <iterator>

namespace w32t {

// ── Free function ─────────────────────────────────────────────────────────────

std::uint16_t readUint16LE(const unsigned char* buffer)
{
    return static_cast<std::uint16_t>(buffer[0])
         | static_cast<std::uint16_t>(buffer[1] << 8);
}

// ── Packet ────────────────────────────────────────────────────────────────────

Packet::Packet() : pos(0) {}

// ── Serialisation ─────────────────────────────────────────────────────────────

Packet& Packet::operator<<(const char* data)
{
    if (!data)
        return *this;

    const auto len = static_cast<std::uint16_t>(std::strlen(data) + 1);
    if (len <= 1)
        return *this;

    buffer.reserve(buffer.size() + sizeof(len) + len);

    // Write length prefix (little-endian).
    const auto* lenBytes = reinterpret_cast<const std::uint8_t*>(&len);
    buffer.insert(buffer.end(), lenBytes, lenBytes + sizeof(len));

    // Write payload (including null terminator).
    buffer.insert(buffer.end(),
                  reinterpret_cast<const std::uint8_t*>(data),
                  reinterpret_cast<const std::uint8_t*>(data) + len);

    return *this;
}

Packet& Packet::operator<<(unsigned int data)
{
    const auto* bytes = reinterpret_cast<const std::uint8_t*>(&data);
    buffer.insert(buffer.end(), bytes, bytes + sizeof(data));
    return *this;
}

// ── Deserialisation ───────────────────────────────────────────────────────────

Packet& Packet::operator>>(char* data)
{
    if (buffer.empty() || pos + sizeof(std::uint16_t) > buffer.size())
        return *this;

    // Read 16-bit little-endian length prefix.
    const std::uint16_t len = readUint16LE(&buffer[pos]);
    pos += sizeof(std::uint16_t);

    if (pos + len > buffer.size())
        return *this;

    std::memcpy(data, &buffer[pos], len);
    pos += len;

    // Ensure null termination.
    data[len] = '\0';

    return *this;
}

Packet& Packet::operator>>(unsigned int& data)
{
    if (pos + sizeof(data) > buffer.size())
        return *this;

    std::memcpy(&data, &buffer[pos], sizeof(data));
    pos += sizeof(data);
    return *this;
}

} // namespace w32t
