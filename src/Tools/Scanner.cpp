#include <win32tools/Tools/Scanner.hpp>

#include <algorithm>    // std::fill
#include <array>

namespace w32t {

    // ─────────────────────────────────────────────────────────────────────────────
    //  Pattern builders
    // ─────────────────────────────────────────────────────────────────────────────

    bool Pattern::from_ida(std::string_view sig,
        std::uint8_t *out_bytes,
        Pattern &out_pat) noexcept
    {
        if (!out_bytes) return false;

        std::size_t   len = 0;
        std::uint64_t mask = 0;
        const char *p = sig.data();
        const char *end = p + sig.size();

        auto hex = [](char c) -> int {
            if (c >= '0' && c <= '9') return c - '0';
            if (c >= 'A' && c <= 'F') return c - 'A' + 10;
            if (c >= 'a' && c <= 'f') return c - 'a' + 10;
            return -1;
            };

        while (p < end && len < kMaxLen) {
            // Skip spaces.
            while (p < end && *p == ' ') ++p;
            if (p >= end) break;

            if (*p == '?') {
                out_bytes[len] = 0x00;
                ++p;
                if (p < end && *p == '?') ++p;   // consume optional second '?'
            }
            else {
                if (p + 1 >= end) return false;
                const int hi = hex(p[0]);
                const int lo = hex(p[1]);
                if (hi < 0 || lo < 0) return false;
                out_bytes[len] = static_cast<std::uint8_t>((hi << 4) | lo);
                mask |= std::uint64_t{ 1 } << len;
                p += 2;
            }
            ++len;
        }

        if (len == 0) return false;
        out_pat = { out_bytes, mask, len };
        return true;
    }

    bool Pattern::from_mask(const std::uint8_t *bytes,
        const std::uint8_t *mask_arr,
        std::size_t         len,
        Pattern &out_pat) noexcept
    {
        if (!bytes || !mask_arr || len == 0 || len > kMaxLen) return false;

        std::uint64_t mask = 0;
        for (std::size_t i = 0; i < len; ++i)
            if (mask_arr[i]) mask |= std::uint64_t{ 1 } << i;

        out_pat = { bytes, mask, len };
        return true;
    }

    bool Pattern::from_char_mask(const std::uint8_t *bytes,
        const char *char_mask,
        Pattern &out_pat) noexcept
    {
        if (!bytes || !char_mask) return false;
        const std::size_t len = std::strlen(char_mask);
        if (len == 0 || len > kMaxLen) return false;

        std::uint64_t mask = 0;
        for (std::size_t i = 0; i < len; ++i)
            if (char_mask[i] == 'x') mask |= std::uint64_t{ 1 } << i;

        out_pat = { bytes, mask, len };
        return true;
    }

    PatternOwned PatternOwned::from_ida(std::string_view sig)
    {
        PatternOwned o;
        o.storage.resize(kMaxLen);
        if (!Pattern::from_ida(sig, o.storage.data(), o.pat))
            o.pat = {};
        return o;
    }

    PatternOwned PatternOwned::from_char_mask(const std::uint8_t *bytes,
        const char *char_mask)
    {
        PatternOwned o;
        const std::size_t len = char_mask ? std::strlen(char_mask) : 0;
        if (len == 0 || len > kMaxLen) return o;

        o.storage.assign(bytes, bytes + len);
        Pattern::from_char_mask(o.storage.data(), char_mask, o.pat);
        return o;
    }

    // ─────────────────────────────────────────────────────────────────────────────
    //  Internal: build BMH bad-character skip table from concrete bytes only.
    //
    //  For each byte value b, skip[b] = distance we can safely jump when b appears
    //  at position (off + pat.len - 1) and does NOT match the last concrete byte.
    //  Wildcards are treated as "could be anything" so they don't contribute a
    //  useful skip — we default to 1 for those positions.
    // ─────────────────────────────────────────────────────────────────────────────

    struct SkipTable {
        std::array<std::size_t, 256> tbl{};

        explicit SkipTable(const Pattern &pat) noexcept
        {
            tbl.fill(pat.len);
            // Only populate from byte positions that are concrete (bit set in mask),
            // and exclude the very last position (standard BMH).
            for (std::size_t i = 0; i + 1 < pat.len; ++i)
                if ((pat.mask >> i) & 1u)
                    tbl[pat.bytes[i]] = pat.len - 1u - i;
        }

        [[nodiscard]] std::size_t operator[](std::uint8_t b) const noexcept
        {
            return tbl[b];
        }
    };

    // ─────────────────────────────────────────────────────────────────────────────
    //  Core region scanner
    // ─────────────────────────────────────────────────────────────────────────────

    const std::uint8_t *
        scan_region(const std::uint8_t *base,
            std::size_t         size,
            const Pattern &pat,
            std::size_t         align) noexcept
    {
        if (!base || pat.len == 0 || size < pat.len) return nullptr;

        const std::size_t   limit = size - pat.len;
        const std::uint64_t mask = pat.mask;
        const std::uint8_t *pb = pat.bytes;
        const std::size_t   step = (align > 1) ? align : 1;

        // ── Fast path: first byte is concrete — use BMH ──────────────────────────
        if (mask & 1u) {
            const SkipTable skip(pat);
            const std::uint8_t  first = pb[0];

            // Find the index of the last concrete byte (for the BMH anchor check).
            std::size_t last_concrete = pat.len - 1;
            while (last_concrete > 0 && !((mask >> last_concrete) & 1u))
                --last_concrete;
            const std::uint8_t last_byte = pb[last_concrete];

            std::size_t off = 0;
            while (off <= limit) {
                // Alignment snap.
                if (step > 1) {
                    const std::size_t rem = off % step;
                    if (rem) { off += step - rem; continue; }
                }

                // BMH: inspect the last concrete byte first to maximise skip distance.
                if (base[off + last_concrete] != last_byte) {
                    const std::size_t jump = skip[base[off + pat.len - 1]];
                    off += (jump > step) ? jump : step;
                    continue;
                }

                // First byte quick-check before full verify.
                if (base[off] != first) {
                    off += step;
                    continue;
                }

                // Full inner verify (skips bit 0 and last_concrete, already checked).
                bool match = true;
                for (std::size_t i = 1; i < pat.len; ++i) {
                    if (i == last_concrete) continue;    // already checked above
                    if (((mask >> i) & 1u) && base[off + i] != pb[i]) {
                        match = false;
                        break;
                    }
                }
                if (match) return base + off;
                off += step;
            }
            return nullptr;
        }

        // ── Slow path: wildcard first byte — linear walk ─────────────────────────
        // Find the first concrete byte to use as a cheaper anchor.
        std::size_t anchor = 0;
        for (std::size_t i = 1; i < pat.len; ++i) {
            if ((mask >> i) & 1u) { anchor = i; break; }
        }

        for (std::size_t off = 0; off <= limit; off += step) {
            // Anchor pre-check.
            if (anchor && base[off + anchor] != pb[anchor]) continue;

            bool match = true;
            for (std::size_t i = 0; i < pat.len; ++i) {
                if (i == anchor) continue;
                if (((mask >> i) & 1u) && base[off + i] != pb[i]) {
                    match = false;
                    break;
                }
            }
            if (match) return base + off;
        }
        return nullptr;
    }

    // ─────────────────────────────────────────────────────────────────────────────
    //  High-level process scanners
    // ─────────────────────────────────────────────────────────────────────────────

    std::uintptr_t
        scan(std::uintptr_t start,
            std::uintptr_t end,
            const Pattern &pat,
            std::size_t    align) noexcept
    {
        auto *cur = reinterpret_cast<const std::uint8_t *>(start);
        auto *bound = reinterpret_cast<const std::uint8_t *>(end);

        while (cur < bound) {
            MEMORY_BASIC_INFORMATION mbi{};
            if (!VirtualQuery(cur, &mbi, sizeof(mbi))) break;

            if (is_readable(mbi)) {
                auto *region = static_cast<const std::uint8_t *>(mbi.BaseAddress);
                auto *scan_start = (region < reinterpret_cast<const std::uint8_t *>(start))
                    ? reinterpret_cast<const std::uint8_t *>(start)
                    : region;

                std::size_t region_left =
                    mbi.RegionSize - static_cast<std::size_t>(scan_start - region);

                if (scan_start + region_left > bound)
                    region_left = static_cast<std::size_t>(bound - scan_start);

                if (const std::uint8_t *hit =
                    scan_region(scan_start, region_left, pat, align))
                    return reinterpret_cast<std::uintptr_t>(hit);
            }

            cur = static_cast<const std::uint8_t *>(mbi.BaseAddress) + mbi.RegionSize;
        }
        return 0;
    }

    // ─────────────────────────────────────────────────────────────────────────────

    std::size_t
        scan_multi(std::uintptr_t  start,
            std::uintptr_t  end,
            const Pattern *pats,
            std::uintptr_t *results,
            std::size_t     pat_count,
            std::size_t     align) noexcept
    {
        if (!pats || !results || pat_count == 0) return 0;
        // Typed zero-fill: avoids the SAL C6385 "readable size is N bytes but 8
        // may be read" warning that a raw memset triggers when the analyser cannot
        // prove the buffer covers pat_count elements of uintptr_t.
        for (std::size_t i = 0; i < pat_count; ++i) results[i] = 0;

        auto *cur = reinterpret_cast<const std::uint8_t *>(start);
        auto *bound = reinterpret_cast<const std::uint8_t *>(end);
        std::size_t found = 0;
        std::size_t pending = pat_count;   // tracks how many patterns still need a hit

        while (cur < bound && pending > 0) {
            MEMORY_BASIC_INFORMATION mbi{};
            if (!VirtualQuery(cur, &mbi, sizeof(mbi))) break;

            if (is_readable(mbi)) {
                auto *region = static_cast<const std::uint8_t *>(mbi.BaseAddress);
                auto *scan_start = (region < reinterpret_cast<const std::uint8_t *>(start))
                    ? reinterpret_cast<const std::uint8_t *>(start)
                    : region;

                std::size_t region_left =
                    mbi.RegionSize - static_cast<std::size_t>(scan_start - region);

                if (scan_start + region_left > bound)
                    region_left = static_cast<std::size_t>(bound - scan_start);

                for (std::size_t p = 0; p < pat_count; ++p) {
                    if (results[p]) continue;   // already found — skip entirely

                    if (const std::uint8_t *hit =
                        scan_region(scan_start, region_left, pats[p], align)) {
                        results[p] = reinterpret_cast<std::uintptr_t>(hit);
                        ++found;
                        --pending;
                    }
                }
            }

            cur = static_cast<const std::uint8_t *>(mbi.BaseAddress) + mbi.RegionSize;
        }
        return found;
    }

    // ─────────────────────────────────────────────────────────────────────────────

    std::size_t
        scan_all(std::uintptr_t  start,
            std::uintptr_t  end,
            const Pattern &pat,
            std::uintptr_t *out_buf,
            std::size_t     capacity,
            std::size_t     align) noexcept
    {
        if (!out_buf || capacity == 0) return 0;

        auto *cur = reinterpret_cast<const std::uint8_t *>(start);
        auto *bound = reinterpret_cast<const std::uint8_t *>(end);
        std::size_t count = 0;

        // Minimum advance after a match: at least pat.len bytes when alignment
        // allows it, otherwise the alignment step.  This avoids re-scanning the
        // matched bytes on every call to scan_region.
        const std::size_t min_advance = (align > 1)
            ? align
            : std::max<std::size_t>(pat.len, 1);

        while (cur < bound && count < capacity) {
            MEMORY_BASIC_INFORMATION mbi{};
            if (!VirtualQuery(cur, &mbi, sizeof(mbi))) break;

            if (is_readable(mbi)) {
                auto *region = static_cast<const std::uint8_t *>(mbi.BaseAddress);
                auto *scan_start = (region < reinterpret_cast<const std::uint8_t *>(start))
                    ? reinterpret_cast<const std::uint8_t *>(start)
                    : region;

                std::size_t region_left =
                    mbi.RegionSize - static_cast<std::size_t>(scan_start - region);

                if (scan_start + region_left > bound)
                    region_left = static_cast<std::size_t>(bound - scan_start);

                const std::uint8_t *search = scan_start;
                std::size_t         remaining = region_left;

                while (count < capacity && remaining >= pat.len) {
                    const std::uint8_t *hit = scan_region(search, remaining, pat, align);
                    if (!hit) break;

                    out_buf[count++] = reinterpret_cast<std::uintptr_t>(hit);

                    const std::size_t skip =
                        static_cast<std::size_t>(hit - search) + min_advance;

                    if (skip >= remaining) break;
                    search += skip;
                    remaining -= skip;
                }
            }

            cur = static_cast<const std::uint8_t *>(mbi.BaseAddress) + mbi.RegionSize;
        }
        return count;
    }

} // namespace w32t