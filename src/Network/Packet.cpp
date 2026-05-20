#include <win32tools/Network/Packet.hpp>
#include <cstring>
#include <algorithm>

namespace w32t {

// ── Write ─────────────────────────────────────────────────────────────────────

void Packet::writeRaw(const void* src, std::size_t len)
{
    const auto* p = static_cast<const std::uint8_t*>(src);
    m_buf.insert(m_buf.end(), p, p + len);
}

Packet& Packet::operator<<(bool v)
    { writeLE<std::uint8_t>(v ? 1u : 0u); return *this; }

Packet& Packet::operator<<(std::uint8_t v)
    { writeLE(v); return *this; }

Packet& Packet::operator<<(std::uint16_t v)
    { writeLE(v); return *this; }

Packet& Packet::operator<<(std::uint32_t v)
    { writeLE(v); return *this; }

Packet& Packet::operator<<(std::uint64_t v)
    { writeLE(v); return *this; }

Packet& Packet::operator<<(std::int8_t v)
    { writeLE(v); return *this; }

Packet& Packet::operator<<(std::int16_t v)
    { writeLE(v); return *this; }

Packet& Packet::operator<<(std::int32_t v)
    { writeLE(v); return *this; }

Packet& Packet::operator<<(std::int64_t v)
    { writeLE(v); return *this; }

Packet& Packet::operator<<(float v)
    { writeLE(v); return *this; }

Packet& Packet::operator<<(double v)
    { writeLE(v); return *this; }

Packet& Packet::operator<<(const char* v)
{
    if (!v) { writeLE<std::uint16_t>(0); return *this; }
    std::uint16_t len = static_cast<std::uint16_t>(std::strlen(v));
    writeLE(len);
    writeRaw(v, len);
    return *this;
}

Packet& Packet::operator<<(const std::string& v)
{
    std::uint16_t len = static_cast<std::uint16_t>(v.size());
    writeLE(len);
    writeRaw(v.data(), len);
    return *this;
}

// ── Read ──────────────────────────────────────────────────────────────────────

void Packet::readRaw(void* dst, std::size_t len)
{
    if (!canRead(len)) return;
    std::memcpy(dst, m_buf.data() + pos, len);
    pos += len;
}

Packet& Packet::operator>>(bool& v)
    { std::uint8_t b = 0; readLE(b); v = (b != 0); return *this; }

Packet& Packet::operator>>(std::uint8_t& v)
    { readLE(v); return *this; }

Packet& Packet::operator>>(std::uint16_t& v)
    { readLE(v); return *this; }

Packet& Packet::operator>>(std::uint32_t& v)
    { readLE(v); return *this; }

Packet& Packet::operator>>(std::uint64_t& v)
    { readLE(v); return *this; }

Packet& Packet::operator>>(std::int8_t& v)
    { readLE(v); return *this; }

Packet& Packet::operator>>(std::int16_t& v)
    { readLE(v); return *this; }

Packet& Packet::operator>>(std::int32_t& v)
    { readLE(v); return *this; }

Packet& Packet::operator>>(std::int64_t& v)
    { readLE(v); return *this; }

Packet& Packet::operator>>(float& v)
    { readLE(v); return *this; }

Packet& Packet::operator>>(double& v)
    { readLE(v); return *this; }

Packet& Packet::operator>>(char* v)
{
    std::uint16_t len = 0;
    if (!readLE(len) || !v) return *this;
    if (canRead(len)) {
        std::memcpy(v, m_buf.data() + pos, len);
        pos += len;
    }
    v[len] = '\0';
    return *this;
}

Packet& Packet::operator>>(std::string& v)
{
    std::uint16_t len = 0;
    if (!readLE(len)) return *this;
    if (canRead(len)) {
        v.assign(reinterpret_cast<const char*>(m_buf.data() + pos), len);
        pos += len;
    }
    return *this;
}

} // namespace w32t