#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <windows.h>

#include <string>

namespace w32t {

/// @brief Injects a DLL into a target process using the CreateRemoteThread
///        + LoadLibraryA technique.
///
/// Usage:
/// @code
///   w32t::Inject injector("C:\\path\\to\\payload.dll");
///   injector.injectIntoProcess(targetPid);
/// @endcode
class Inject {
public:
    Inject();
    explicit Inject(const std::string& dllPath);
    ~Inject() = default;

    // ── Configuration ────────────────────────────────────────────────────────

    /// @brief Set or change the DLL path used for injection.
    /// @return false if @p dllPath is empty.
    bool setDllPath(const std::string& dllPath);

    /// @brief Return the currently configured DLL path.
    [[nodiscard]] const std::string& dllPath() const noexcept
    {
        return m_dllPath;
    }

    // ── Injection ────────────────────────────────────────────────────────────

    /// @brief Inject m_dllPath into @p targetPid via CreateRemoteThread.
    ///
    /// Steps performed:
    ///  1. Resolve LoadLibraryA in the local kernel32.dll.
    ///  2. OpenProcess with the required access rights.
    ///  3. VirtualAllocEx + WriteProcessMemory the DLL path string.
    ///  4. CreateRemoteThread(LoadLibraryA, remoteDllPathAddr).
    ///  5. WaitForSingleObject, inspect exit code, clean up.
    ///
    /// @param targetPid  ID of the target process.
    /// @return true if LoadLibraryA succeeded inside the remote process.
    bool injectIntoProcess(DWORD targetPid);

    bool injectWithShellcode(DWORD targetPid);

    /// @brief Convenience overload that also sets the DLL path.
    /// @return false if @p dllPath is empty or @p targetPid is 0.
    bool injectIntoProcess(DWORD targetPid, const std::string& dllPath);

private:
    std::string m_dllPath;
    DWORD       m_processAccess; ///< Flags passed to OpenProcess.
};

} // namespace w32t