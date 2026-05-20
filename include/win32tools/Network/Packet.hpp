#ifndef W32T_PACKET_HPP
#define W32T_PACKET_HPP

// ─────────────────────────────────────────────────────────────────────────────
//  w32t :: Packet
//
//  Simple binary serialisation buffer.
//  Supports:  uint8/16/32/64, int variants, float, double, bool, C-string,
//             raw byte spans, and std::string.
//  Wire layout is little-endian; strings are length-prefixed (uint16).
// ─────────────────────────────────────────────────────────────────────────────

#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

namespace w32t {

class Packet {
public:
    Packet() = default;
    explicit Packet(std::size_t reserve) { m_buf.reserve(reserve); }

    // ── Cursor ────────────────────────────────────────────────────────────────
    std::size_t pos = 0;   ///< read cursor

    // ── Metadata ──────────────────────────────────────────────────────────────
    [[nodiscard]] std::size_t         size()  const noexcept { return m_buf.size(); }
    [[nodiscard]] bool                empty() const noexcept { return m_buf.empty(); }
    [[nodiscard]] const std::uint8_t* data()  const noexcept { return m_buf.data(); }
    [[nodiscard]] std::uint8_t*       data()        noexcept { return m_buf.data(); }

    void clear() noexcept { m_buf.clear(); pos = 0; }
    void resize(std::size_t n) { m_buf.resize(n); }

    // ── Write ─────────────────────────────────────────────────────────────────
    Packet& operator<<(bool              v);
    Packet& operator<<(std::uint8_t      v);
    Packet& operator<<(std::uint16_t     v);
    Packet& operator<<(std::uint32_t     v);
    Packet& operator<<(std::uint64_t     v);
    Packet& operator<<(std::int8_t       v);
    Packet& operator<<(std::int16_t      v);
    Packet& operator<<(std::int32_t      v);
    Packet& operator<<(std::int64_t      v);
    Packet& operator<<(float             v);
    Packet& operator<<(double            v);
    Packet& operator<<(const char*       v);   ///< null-terminated → uint16 len + bytes
    Packet& operator<<(const std::string& v);

    // Write raw bytes (no length prefix).
    void writeRaw(const void* src, std::size_t len);

    // ── Read ──────────────────────────────────────────────────────────────────
    Packet& operator>>(bool&             v);
    Packet& operator>>(std::uint8_t&     v);
    Packet& operator>>(std::uint16_t&    v);
    Packet& operator>>(std::uint32_t&    v);
    Packet& operator>>(std::uint64_t&    v);
    Packet& operator>>(std::int8_t&      v);
    Packet& operator>>(std::int16_t&     v);
    Packet& operator>>(std::int32_t&     v);
    Packet& operator>>(std::int64_t&     v);
    Packet& operator>>(float&            v);
    Packet& operator>>(double&           v);
    Packet& operator>>(char*             v);   ///< reads uint16 len then copies + null
    Packet& operator>>(std::string&      v);

    // Read raw bytes (no length prefix).
    void readRaw(void* dst, std::size_t len);

    [[nodiscard]] bool canRead(std::size_t n) const noexcept
    { return pos + n <= m_buf.size(); }

private:
    std::vector<std::uint8_t> m_buf;

    template<typename T>
    void writeLE(T v) {
        const auto* p = reinterpret_cast<const std::uint8_t*>(&v);
        for (std::size_t i = 0; i < sizeof(T); ++i)
            m_buf.push_back(p[i]);
    }

    template<typename T>
    bool readLE(T& v) {
        if (!canRead(sizeof(T))) return false;
        std::memcpy(&v, m_buf.data() + pos, sizeof(T));
        pos += sizeof(T);
        return true;
    }
};

} // namespace w32t

#endif // W32T_PACKET_HPP