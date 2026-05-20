#pragma once

#include <cstdint>
#include <vector>

namespace w32t {

/// @brief Decode a 16-bit little-endian value from a raw byte buffer.
/// @param buffer  Pointer to at least 2 bytes.
[[nodiscard]] std::uint16_t readUint16LE(const unsigned char* buffer);

/// @brief Binary serialisation / deserialisation buffer.
///
/// Data is framed with a 16-bit little-endian length prefix so receivers
/// can determine message boundaries without out-of-band signalling.
///
/// ### Writing
/// @code
///   Packet pkt;
///   pkt << "hello";        // prefixed with uint16 length
///   pkt << 42u;            // raw uint32
/// @endcode
///
/// ### Reading
/// @code
///   char str[256];
///   unsigned int n = 0;
///   pkt >> str;
///   pkt >> n;
/// @endcode
struct Packet {
    Packet();
    ~Packet() = default;

    // ── Serialisation ────────────────────────────────────────────────────────

    /// @brief Append a null-terminated C string with a uint16 length prefix.
    Packet& operator<<(const char* data);

    /// @brief Append a uint32 as raw bytes (no prefix).
    Packet& operator<<(unsigned int data);

    // ── Deserialisation ──────────────────────────────────────────────────────

    /// @brief Read a length-prefixed C string from the current position.
    ///
    /// @p data must point to a buffer large enough to hold the string
    /// (including the null terminator). The caller is responsible for
    /// bounds checking.
    Packet& operator>>(char* data);

    /// @brief Read a raw uint32 from the current position.
    Packet& operator>>(unsigned int& data);

    // ── Inspection ───────────────────────────────────────────────────────────

    /// @brief Total number of bytes currently in the buffer.
    [[nodiscard]] std::size_t size() const noexcept { return buffer.size(); }

    // Public so NetworkSocket can pass the buffer pointer directly to send/recv.
    std::vector<std::uint8_t> buffer;
    std::size_t               pos; ///< Current read cursor.
};

} // namespace w32t
