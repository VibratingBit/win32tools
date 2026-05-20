#include <win32tools/Tools/Core.hpp>

#include <cstring>

namespace w32t {

    Core::Core()
        : m_procAccess(PROCESS_VM_READ | PROCESS_VM_WRITE |
            PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION |
            PROCESS_TERMINATE),
        m_snapFlags(TH32CS_SNAPPROCESS | TH32CS_SNAPMODULE32 | TH32CS_SNAPMODULE),
        m_lastAlloc(0)
    {
    }

    // ── Process discovery ─────────────────────────────────────────────────────────

    DWORD Core::processIdFromWindow(const std::string &windowTitle,
        const std::string &className)
    {
        // Both empty — nothing to search for.
        if (windowTitle.empty() && className.empty())
            return 0;

        // FindWindowA(lpClassName, lpWindowName)
        //   Either argument may be nullptr to act as a wildcard.
        const char *cls = className.empty() ? nullptr : className.c_str();
        const char *title = windowTitle.empty() ? nullptr : windowTitle.c_str();

        HWND wnd = FindWindowA(cls, title);
        if (!wnd)
            return 0;

        DWORD pid = 0;
        GetWindowThreadProcessId(wnd, &pid);
        return pid;
    }

    std::vector<DWORD> Core::processIdListFromExe(const std::string &exeName)
    {
        std::vector<DWORD> results;
        if (exeName.empty())
            return results;

        PROCESSENTRY32 entry{};
        entry.dwSize = sizeof(entry);

        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snap == INVALID_HANDLE_VALUE)
            return results;

        if (Process32First(snap, &entry)) {
            do {
                if (exeName == entry.szExeFile)
                    results.push_back(entry.th32ProcessID);
            } while (Process32Next(snap, &entry));
        }
        CloseHandle(snap);
        return results;
    }

    DWORD Core::processIdFromExe(const std::string &exeName)
    {
        if (exeName.empty())
            return 0;

        PROCESSENTRY32 entry{};
        entry.dwSize = sizeof(entry);

        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snap == INVALID_HANDLE_VALUE)
            return 0;

        DWORD pid = 0;
        if (Process32First(snap, &entry)) {
            do {
                if (exeName == entry.szExeFile) {
                    pid = entry.th32ProcessID;
                    break;
                }
            } while (Process32Next(snap, &entry));
        }
        CloseHandle(snap);
        return pid;
    }

    // ── Module info ───────────────────────────────────────────────────────────────

    std::unique_ptr<MODULEINFO> Core::getInternalModuleInfo(const std::string &moduleName)
    {
        if (moduleName.empty())
            return nullptr;

        HMODULE hMod = GetModuleHandleA(moduleName.c_str());
        if (!hMod)
            return nullptr;

        MODULEINFO info{};
        if (!GetModuleInformation(GetCurrentProcess(), hMod, &info, sizeof(info)))
            return nullptr;

        return std::make_unique<MODULEINFO>(info);
    }

    std::unique_ptr<MODULEENTRY32> Core::getModuleFromPid(DWORD              pid,
        const std::string &moduleName)
    {
        if (moduleName.empty() || pid == 0)
            return nullptr;

        // TH32CS_SNAPMODULE can return ERROR_BAD_LENGTH on the first call for
        // 64-bit processes when the snapshot is still being built — retry once.
        constexpr DWORD snapFlags = TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32;
        HANDLE snap = INVALID_HANDLE_VALUE;

        for (int attempt = 0; attempt < 3 && snap == INVALID_HANDLE_VALUE; ++attempt) {
            snap = CreateToolhelp32Snapshot(snapFlags, pid);
            if (snap == INVALID_HANDLE_VALUE && GetLastError() == ERROR_BAD_LENGTH)
                Sleep(10);
        }

        if (snap == INVALID_HANDLE_VALUE)
            return nullptr;

        MODULEENTRY32 entry{};
        entry.dwSize = sizeof(entry);

        std::unique_ptr<MODULEENTRY32> result;
        if (Module32First(snap, &entry)) {
            do {
                if (moduleName == entry.szModule) {
                    result = std::make_unique<MODULEENTRY32>(entry);
                    break;
                }
            } while (Module32Next(snap, &entry));
        }
        CloseHandle(snap);
        return result;
    }

    // ── Remote memory operations ──────────────────────────────────────────────────

    uintptr_t Core::allocRemote(HANDLE processHandle, uintptr_t size)
    {
        LPVOID addr = VirtualAllocEx(processHandle, nullptr, size,
            MEM_COMMIT, PAGE_EXECUTE_READWRITE);
        if (!addr)
            return 0;

        m_lastAlloc = reinterpret_cast<uintptr_t>(addr);
        return m_lastAlloc;
    }

    uintptr_t Core::writeCodeCaveRemote(HANDLE             processHandle,
        const std::uint8_t *data,
        uintptr_t           size)
    {
        if (!data || size == 0)
            return 0;

        uintptr_t base = allocRemote(processHandle, size);
        if (!base)
            return 0;

        uintptr_t written = writeMemoryRemote(processHandle,
            reinterpret_cast<std::uint8_t *>(base),
            data, size);
        if (written > 0)
            m_lastAlloc += written;

        return base;
    }

    uintptr_t Core::writeMemoryRemote(HANDLE              processHandle,
        std::uint8_t *destination,
        const std::uint8_t *data,
        uintptr_t           size)
    {
        if (!destination || !data || size == 0)
            return 0;

        DWORD    oldProtect = 0;
        SIZE_T   bytesWritten = 0;

        if (!VirtualProtectEx(processHandle, destination, size,
            PAGE_EXECUTE_READWRITE, &oldProtect))
            return 0;

        WriteProcessMemory(processHandle, destination, data, size, &bytesWritten);

        // Restore original protection (best-effort; ignore failure).
        VirtualProtectEx(processHandle, destination, size, oldProtect, &oldProtect);

        return static_cast<uintptr_t>(bytesWritten);
    }

    // ── Byte helpers ──────────────────────────────────────────────────────────────

    std::vector<std::uint8_t> Core::toBytes(DWORD value, std::size_t length)
    {
        if (value == 0)
            return {};

        std::size_t count = (length == 0) ? sizeof(DWORD) : length;
        std::vector<std::uint8_t> bytes;
        bytes.reserve(count);

        for (std::size_t i = 0; i < count; ++i)
            bytes.push_back(static_cast<std::uint8_t>((value >> (i * 8)) & 0xFF));

        return bytes;
    }

    void Core::appendBytes(std::vector<std::uint8_t> &dest,
        const char *src,
        std::size_t                 length)
    {
        if (!src)
            return;

        std::size_t n = (length == 0) ? std::strlen(src) : length;
        if (n > 0)
            dest.insert(dest.end(), src, src + n);
    }

    void Core::appendBytes(std::vector<std::uint8_t> &dest,
        DWORD                       value,
        std::size_t                 length)
    {
        auto bytes = toBytes(value, length);
        if (!bytes.empty())
            dest.insert(dest.end(), bytes.begin(), bytes.end());
    }

    void Core::appendBytes(std::vector<std::uint8_t> &dest,
        const std::vector<std::uint8_t> &src)
    {
        if (!src.empty())
            dest.insert(dest.end(), src.begin(), src.end());
    }

} // namespace w32t