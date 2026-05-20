#ifndef W32T_HAXHELPER_HPP
#define W32T_HAXHELPER_HPP

// Core.hpp provides the FULL class definition — a forward-declaration is NOT
// sufficient because HaxHelper publicly inherits from Core.
#include <win32tools/Tools/Core.hpp>

// Scanner — Pattern, PatternOwned, scan_region, scan, scan_multi, scan_all,
//           findPattern (legacy shim), is_readable.
#include <win32tools/Tools/Scanner.hpp>

// tlhelp32 for MODULEENTRY32 (transitively included via Core.hpp on most
// win32tools builds, but explicit here for correctness).
#include <tlhelp32.h>

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace w32t {

    // ─────────────────────────────────────────────────────────────────────────────

    class HaxHelper : public Core {
    public:
        explicit HaxHelper(const std::string &targetExe);

        // ── Memory dump ───────────────────────────────────────────────────────────

        /// Dump the target module into m_dumpedMemory.
        /// Idempotent — returns true immediately if already successfully dumped.
        /// Call invalidateDump() first to force a fresh read.
        bool dumpMemory();

        /// Discard the cached dump so the next dumpMemory() / findExternal* call
        /// re-reads the target process.
        void invalidateDump() noexcept
        {
            m_dumpedMemory.clear();
            m_memoryDumped = false;
            m_moduleBase = 0;
            m_moduleSize = 0;
        }

        [[nodiscard]] bool        isDumped()   const noexcept { return m_memoryDumped; }
        [[nodiscard]] std::size_t dumpedSize() const noexcept { return m_dumpedMemory.size(); }

        // ── Pattern scanning — returns addresses in the TARGET process ────────────

        /// Classic byte-array + char-mask scan ("xxx??x").
        [[nodiscard]]
        std::uintptr_t findExternalBytes(MODULEENTRY32       moduleEntry,
            const std::uint8_t *pattern,
            const char *mask);

        /// IDA-style signature scan ("48 8B ? ? 05 ?? AB").
        /// No separate mask string required.
        [[nodiscard]]
        std::uintptr_t findExternalIda(MODULEENTRY32    moduleEntry,
            std::string_view idaSig);

        // ── DLL injection ─────────────────────────────────────────────────────────

        static bool injectDll(DWORD targetPid, std::string_view dllPath);

    private:
        std::string               m_targetExe;
        std::vector<std::uint8_t> m_dumpedMemory;
        bool                      m_memoryDumped = false;
        std::uintptr_t            m_moduleBase = 0;   ///< cached remote base address
        std::size_t               m_moduleSize = 0;   ///< cached remote image size

        /// Translate a pointer into m_dumpedMemory to its equivalent address in
        /// the remote process.
        [[nodiscard]]
        std::uintptr_t translateToRemote(std::uintptr_t dumpedAddr,
            std::uintptr_t remoteBase) const noexcept;
    };

} // namespace w32t

#endif // W32T_HAXHELPER_HPP