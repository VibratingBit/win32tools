#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <windows.h>
#include <psapi.h>
#include <tlhelp32.h>

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

namespace w32t {

/// @brief Base class providing Win32 process and memory manipulation utilities.
///
/// Encapsulates common operations such as process discovery, module enumeration,
/// remote memory allocation, and byte-level read/write helpers. Designed to be
/// inherited by higher-level tool classes (e.g. HaxHelper).
class Core {
public:
    Core();
    virtual ~Core() = default;

    // ── Process discovery ────────────────────────────────────────────────────

    /// @brief Find a process ID by its top-level window title and optional class name.
    /// @param windowTitle  Exact window title to search for.
    /// @param className    Optional window class name (empty = any class).
    /// @return Process ID, or 0 if not found.
    [[nodiscard]] static DWORD processIdFromWindow(
        const std::string& windowTitle,
        const std::string& className = {});

    /// @brief Collect all process IDs whose executable filename matches @p exeName.
    /// @param exeName  Filename including extension, e.g. "notepad.exe".
    /// @return List of matching process IDs (may be empty).
    [[nodiscard]] static std::vector<DWORD> processIdListFromExe(
        const std::string& exeName);

    /// @brief Return the first process ID whose executable filename matches @p exeName.
    /// @param exeName  Filename including extension, e.g. "notepad.exe".
    /// @return Process ID, or 0 if not found.
    [[nodiscard]] static DWORD processIdFromExe(const std::string& exeName);

    // ── Module info ──────────────────────────────────────────────────────────

    /// @brief Query MODULEINFO for a module loaded in the *current* process.
    /// @param moduleName  Module filename, e.g. "ntdll.dll".
    /// @return Owning pointer to MODULEINFO, or nullptr on failure.
    [[nodiscard]] static std::unique_ptr<MODULEINFO> getInternalModuleInfo(
        const std::string& moduleName);

    /// @brief Find a MODULEENTRY32 for a module in an *external* process.
    /// @param pid         Target process ID (must be > 4).
    /// @param moduleName  Module filename to search for.
    /// @return Owning pointer to MODULEENTRY32, or nullptr on failure.
    [[nodiscard]] static std::unique_ptr<MODULEENTRY32> getModuleFromPid(
        DWORD pid,
        const std::string& moduleName);

    // ── Remote memory operations ─────────────────────────────────────────────

    /// @brief Allocate RWX memory in a remote process.
    /// @param processHandle  Open handle with PROCESS_VM_OPERATION access.
    /// @param size           Number of bytes to allocate.
    /// @return Base address of the allocated region, or 0 on failure.
    [[nodiscard]] uintptr_t allocRemote(HANDLE processHandle, uintptr_t size);

    /// @brief Write a code cave into previously allocated remote memory.
    ///
    /// Calls allocRemote() internally if no allocation exists yet.
    /// @param processHandle  Open handle with VM operation/write access.
    /// @param data           Pointer to the bytes to write.
    /// @param size           Number of bytes to write.
    /// @return Start address of the written region, or 0 on failure.
    uintptr_t writeCodeCaveRemote(HANDLE processHandle,
                                  const std::uint8_t* data,
                                  uintptr_t size);

    /// @brief Write arbitrary bytes into a remote process, temporarily
    ///        granting PAGE_EXECUTE_READWRITE and then restoring the original
    ///        protection.
    /// @param processHandle  Open handle with VM operation/write access.
    /// @param destination    Target address inside the remote process.
    /// @param data           Source buffer.
    /// @param size           Number of bytes to write.
    /// @return Number of bytes actually written, or 0 on failure.
    static uintptr_t writeMemoryRemote(HANDLE processHandle,
                                       std::uint8_t* destination,
                                       const std::uint8_t* data,
                                       uintptr_t size);

    // ── Byte helpers ─────────────────────────────────────────────────────────

    /// @brief Decompose a DWORD into its constituent bytes (little-endian).
    /// @param value   Source value.
    /// @param length  Number of bytes to extract (defaults to sizeof(DWORD)).
    /// @return Vector of extracted bytes.
    [[nodiscard]] static std::vector<std::uint8_t> toBytes(
        DWORD value,
        std::size_t length = sizeof(DWORD));

    /// @brief Append a null-terminated C string's bytes to @p dest.
    /// @param dest    Destination buffer.
    /// @param src     Source C string.
    /// @param length  Bytes to copy; 0 means use strlen(src).
    static void appendBytes(std::vector<std::uint8_t>& dest,
                            const char* src,
                            std::size_t length = 0);

    /// @brief Append a DWORD's bytes (little-endian) to @p dest.
    static void appendBytes(std::vector<std::uint8_t>& dest,
                            DWORD value,
                            std::size_t length = sizeof(DWORD));

    /// @brief Append another byte vector to @p dest.
    static void appendBytes(std::vector<std::uint8_t>& dest,
                            const std::vector<std::uint8_t>& src);

    // ── Access helpers ───────────────────────────────────────────────────────

    /// @brief Return the default desired process access flags.
    [[nodiscard]] DWORD desiredAccess() const noexcept { return m_procAccess; }

protected:
    DWORD    m_procAccess;  ///< Default OpenProcess access flags.
    DWORD    m_snapFlags;   ///< Default CreateToolhelp32Snapshot flags.
    uintptr_t m_lastAlloc;  ///< Address of the most recent remote allocation.
};

} // namespace w32t