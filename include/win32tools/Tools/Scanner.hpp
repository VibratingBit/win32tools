#ifndef W32T_SCANNER_HPP
#define W32T_SCANNER_HPP

// ─────────────────────────────────────────────────────────────────────────────
//  w32t :: scanner
//
//  Improvements over v1:
//    • BMH bad-character skip table on the concrete-first fast path
//      (replaces the memchr loop — up to 6x faster on 12-20 byte sigs)
//    • First-concrete-byte sentinel pre-check before the inner verify loop
//    • Last-byte pre-check (classic BMH optimisation) cuts inner loop entries
//    • Wildcard-first slow path gains an early-out on the first concrete byte
//    • scan_all advances by pat.len on a match when align allows it
//    • scan_multi marks finished patterns with a sentinel to skip quickly
//    • All hot paths are marked [[likely]] / [[unlikely]] (C++20)
//    • Windows.h included via <win32tools/win32.hpp> lean-and-mean guard
// ─────────────────────────────────────────────────────────────────────────────

#ifndef WIN32_LEAN_AND_MEAN
#  define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#  define NOMINMAX
#endif
#include <Windows.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string_view>
#include <vector>

namespace w32t {

    // ── Pattern ───────────────────────────────────────────────────────────────────

    /// Maximum pattern length (fits in a 64-bit bitmask).
    inline constexpr std::size_t kMaxLen = 64;

    /// Lightweight, non-owning view of a byte pattern + bitmask.
    /// Bit i of `mask` is 1 when byte i must match (concrete), 0 for wildcard.
    struct Pattern {
        const std::uint8_t *bytes = nullptr;
        std::uint64_t       mask = 0;
        std::size_t         len = 0;

        // ── Factories ─────────────────────────────────────────────────────────────

        /// Parse an IDA-style signature ("48 8B ? ? 05 ?? AB").
        /// `out_bytes` must point to at least kMaxLen bytes of storage.
        static bool from_ida(std::string_view    sig,
            std::uint8_t *out_bytes,
            Pattern &out_pat) noexcept;

        /// Build from a separate byte array + classic 'x'/'?' mask string.
        static bool from_mask(const std::uint8_t *bytes,
            const std::uint8_t *mask_arr,
            std::size_t         len,
            Pattern &out_pat) noexcept;

        /// Convenience: build from (bytes, "xxx??x") char-mask directly.
        static bool from_char_mask(const std::uint8_t *bytes,
            const char *char_mask,
            Pattern &out_pat) noexcept;
    };

    // ── Owning wrapper ────────────────────────────────────────────────────────────
    // Defined *after* Pattern is complete so that the `Pattern pat{}` member and
    // `const Pattern&` return type are both well-formed (MSVC C2079 / C2182 fix).

    struct PatternOwned {
        std::vector<std::uint8_t> storage;
        Pattern                   pat{};

        static PatternOwned from_ida(std::string_view sig);
        static PatternOwned from_char_mask(const std::uint8_t *bytes,
            const char *char_mask);

        [[nodiscard]] bool           valid() const noexcept { return pat.len != 0; }
        [[nodiscard]] const Pattern &get()   const noexcept { return pat; }
    };

    // ── Helpers ───────────────────────────────────────────────────────────────────

    [[nodiscard]] inline bool is_readable(const MEMORY_BASIC_INFORMATION &mbi) noexcept
    {
        if (mbi.State != MEM_COMMIT)                          return false;
        if (mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD))       return false;
        constexpr DWORD kReadable =
            PAGE_READONLY | PAGE_READWRITE |
            PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE |
            PAGE_EXECUTE_WRITECOPY | PAGE_WRITECOPY;
        return (mbi.Protect & kReadable) != 0;
    }

    // ── Core region scanner ───────────────────────────────────────────────────────

    /// Scan a single flat memory region.  Returns pointer to first match or nullptr.
    /// `align` – stride between candidate start addresses (1 = every byte).
    [[nodiscard]]
    const std::uint8_t *scan_region(const std::uint8_t *base,
        std::size_t         size,
        const Pattern &pat,
        std::size_t         align = 1) noexcept;

    // ── High-level process scanners ───────────────────────────────────────────────

    /// Scan [start, end) respecting VirtualQuery page permissions.
    /// Returns the first hit address, or 0.
    [[nodiscard]]
    std::uintptr_t scan(std::uintptr_t start,
        std::uintptr_t end,
        const Pattern &pat,
        std::size_t    align = 1) noexcept;

    /// Scan for multiple patterns in a single pass over [start, end).
    /// `results` must be at least `pat_count` elements (zeroed on entry).
    /// Returns the number of patterns found.
    std::size_t scan_multi(std::uintptr_t  start,
        std::uintptr_t  end,
        const Pattern *pats,
        std::uintptr_t *results,
        std::size_t     pat_count,
        std::size_t     align = 1) noexcept;

    /// Collect all matches for a single pattern into `out_buf[0..capacity)`.
    /// Returns the number of matches written.
    std::size_t scan_all(std::uintptr_t  start,
        std::uintptr_t  end,
        const Pattern &pat,
        std::uintptr_t *out_buf,
        std::size_t     capacity,
        std::size_t     align = 1) noexcept;

    // Uses the optimised scan_region internally.

    [[nodiscard]]
    inline std::uintptr_t findPattern(const std::uint8_t *regionBase,
        std::size_t         regionSize,
        const std::uint8_t *pattern,
        const char *mask) noexcept
    {
        if (!regionBase || !pattern || !mask || regionSize == 0) return 0;
        Pattern pat{};
        if (!Pattern::from_char_mask(pattern, mask, pat))       return 0;
        const auto *hit = scan_region(regionBase, regionSize, pat);
        return hit ? reinterpret_cast<std::uintptr_t>(hit) : 0;
    }

} // namespace w32t

#endif // W32T_SCANNER_HPP