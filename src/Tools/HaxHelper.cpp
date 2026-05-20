#include <win32tools/Tools/HaxHelper.hpp> 
#include <win32tools/Tools/Inject.hpp>   // Inject class — unchanged

#include <iostream>

namespace w32t {

    // ─────────────────────────────────────────────────────────────────────────────
    //  Internal helpers
    // ─────────────────────────────────────────────────────────────────────────────

    namespace {

        /// Attempt to enable SeDebugPrivilege in the current process token.
        /// Required to open handles to processes owned by other users / sessions.
        /// Returns true if the privilege was successfully enabled.
        bool enableDebugPrivilege() noexcept
        {
            HANDLE hToken = nullptr;
            if (!OpenProcessToken(GetCurrentProcess(),
                TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
                &hToken))
                return false;

            LUID luid{};
            if (!LookupPrivilegeValueA(nullptr, "SeDebugPrivilege", &luid)) {
                CloseHandle(hToken);
                return false;
            }

            TOKEN_PRIVILEGES tp{};
            tp.PrivilegeCount = 1;
            tp.Privileges[0].Luid = luid;
            tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

            const bool ok =
                AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), nullptr, nullptr)
                && GetLastError() == ERROR_SUCCESS;

            CloseHandle(hToken);
            return ok;
        }

    } // anonymous namespace

    // ─────────────────────────────────────────────────────────────────────────────
    //  Constructor
    // ─────────────────────────────────────────────────────────────────────────────

    HaxHelper::HaxHelper(const std::string &targetExe)
        : Core()
        , m_targetExe(targetExe)
    {
    }

    // ─────────────────────────────────────────────────────────────────────────────
    //  Memory dump
    // ─────────────────────────────────────────────────────────────────────────────

    bool HaxHelper::dumpMemory()
    {
        // Idempotent: already dumped successfully — nothing to do.
        if (m_memoryDumped) return true;

        if (m_targetExe.empty()) return false;

        // SeDebugPrivilege allows opening handles to cross-session processes.
        // Silently ignored if already enabled or if the caller lacks rights.
        enableDebugPrivilege();

        const DWORD pid = processIdFromExe(m_targetExe);
        if (!pid) {
            std::cerr << "[HaxHelper] Process not found: " << m_targetExe << '\n';
            return false;
        }

        // Request only the access flags needed for ReadProcessMemory.
        // Requesting write / terminate rights will cause OpenProcess to fail on
        // processes owned by other users even with administrator rights.
        constexpr DWORD k_readAccess = PROCESS_VM_READ | PROCESS_QUERY_INFORMATION;
        HANDLE hProc = OpenProcess(k_readAccess, FALSE, pid);
        if (!hProc) {
            std::cerr << "[HaxHelper] OpenProcess failed, error="
                << GetLastError() << '\n';
            return false;
        }

        auto modEntry = getModuleFromPid(pid, m_targetExe);
        if (!modEntry) {
            std::cerr << "[HaxHelper] Module entry not found for: "
                << m_targetExe << '\n';
            CloseHandle(hProc);
            return false;
        }

        // Cache remote base and size so translation doesn't need a module lookup
        // on every findExternal* call.
        m_moduleBase = reinterpret_cast<std::uintptr_t>(modEntry->modBaseAddr);
        m_moduleSize = modEntry->modBaseSize;

        m_dumpedMemory.resize(m_moduleSize);

        SIZE_T bytesRead = 0;
        const BOOL ok = ReadProcessMemory(
            hProc,
            modEntry->modBaseAddr,
            m_dumpedMemory.data(),
            m_dumpedMemory.size(),
            &bytesRead);

        if (!ok) {
            std::cerr << "[HaxHelper] ReadProcessMemory failed, error="
                << GetLastError() << '\n';
            m_dumpedMemory.clear();
            m_moduleBase = 0;
            m_moduleSize = 0;
        }
        else {
            m_dumpedMemory.resize(bytesRead);
        }

        CloseHandle(hProc);
        m_memoryDumped = (ok != FALSE);
        return m_memoryDumped;
    }

    // ─────────────────────────────────────────────────────────────────────────────
    //  Private: address translation
    // ─────────────────────────────────────────────────────────────────────────────

    std::uintptr_t
        HaxHelper::translateToRemote(std::uintptr_t dumpedAddr,
            std::uintptr_t remoteBase) const noexcept
    {
        const std::uintptr_t dumpBase =
            reinterpret_cast<std::uintptr_t>(m_dumpedMemory.data());
        return remoteBase + (dumpedAddr - dumpBase);
    }

    // ─────────────────────────────────────────────────────────────────────────────
    //  Pattern scanning
    // ─────────────────────────────────────────────────────────────────────────────

    std::uintptr_t
        HaxHelper::findExternalBytes(MODULEENTRY32       moduleEntry,
            const std::uint8_t *pattern,
            const char *mask)
    {
        if (!dumpMemory() || m_dumpedMemory.empty()) return 0;

        // Build an optimised Pattern and scan the local dump buffer.
        Pattern pat{};
        if (!Pattern::from_char_mask(pattern, mask, pat)) return 0;

        const std::uint8_t *hit =
            scan_region(m_dumpedMemory.data(), m_dumpedMemory.size(), pat);
        if (!hit) return 0;

        return translateToRemote(reinterpret_cast<std::uintptr_t>(hit),
            reinterpret_cast<std::uintptr_t>(moduleEntry.modBaseAddr));
    }

    std::uintptr_t
        HaxHelper::findExternalIda(MODULEENTRY32    moduleEntry,
            std::string_view idaSig)
    {
        if (!dumpMemory() || m_dumpedMemory.empty()) return 0;

        const auto owned = PatternOwned::from_ida(idaSig);
        if (!owned.valid()) return 0;

        const std::uint8_t *hit =
            scan_region(m_dumpedMemory.data(), m_dumpedMemory.size(), owned.get());
        if (!hit) return 0;

        return translateToRemote(reinterpret_cast<std::uintptr_t>(hit),
            reinterpret_cast<std::uintptr_t>(moduleEntry.modBaseAddr));
    }

    // ─────────────────────────────────────────────────────────────────────────────
    //  DLL injection
    // ─────────────────────────────────────────────────────────────────────────────

    bool HaxHelper::injectDll(DWORD targetPid, std::string_view dllPath)
    {
        // PID 0 = idle process, PID 4 = System — both are unsupported targets.
        if (targetPid == 0 || targetPid == 4) return false;
        if (dllPath.empty())                  return false;

        Inject injector{ std::string{dllPath} };
        return injector.injectIntoProcess(targetPid);
    }

} // namespace w32t