#include <win32tools/Tools/Inject.hpp>

#include <iostream>
#include <filesystem>

std::wstring utf8_to_wide(const std::string &s)
{
    if (s.empty()) return {};

    int len = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, nullptr, 0);
    std::wstring out(len - 1, L'\0'); // exclude null terminator
    MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, out.data(), len);
    return out;
}

// implement NtCreateThreadEx  for optimization  at some point...
// std::cout << "[Inject] Running as admin: " << IsUserAnAdmin() << "\n";


namespace w32t {

Inject::Inject() : m_dllPath{},
    m_processAccess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION |
                      PROCESS_VM_OPERATION  | PROCESS_VM_WRITE | PROCESS_VM_READ)
{}

Inject::Inject(const std::string& dllPath) : Inject()
{
    m_dllPath = dllPath;
}

// ── Configuration ─────────────────────────────────────────────────────────────

bool Inject::setDllPath(const std::string& dllPath)
{
    if (dllPath.empty()) return false;

    m_dllPath = dllPath;
    return true;
}


// x64
bool Inject::injectWithShellcode(DWORD targetPid)
{
    if (m_dllPath.empty() || targetPid == 0) return false;

    HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, targetPid);
    if (!hProc) return false;

    // 1. Get LoadLibraryA address
    LPVOID loadLibAddr = (LPVOID)GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA");

    // 2. Allocate and Write the DLL Path
    size_t pathLen = m_dllPath.size() + 1;
    LPVOID remotePath = VirtualAllocEx(hProc, nullptr, pathLen, MEM_COMMIT, PAGE_READWRITE);
    WriteProcessMemory(hProc, remotePath, m_dllPath.c_str(), pathLen, nullptr);

    /**
     * 3. Construct the x64 Shellcode
     * We need to respect the x64 calling convention (Shadow space + RCX register)
     */
    unsigned char shellcode[] = {
        0x48, 0x83, 0xEC, 0x28,             // sub rsp, 40 (Prepare shadow space)
        0x48, 0xB9, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rcx, [remotePath]
        0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rax, [loadLibAddr]
        0xFF, 0xD0,                         // call rax
        0x48, 0x83, 0xC4, 0x28,             // add rsp, 40 (Cleanup)
        0xC3                                // ret
    };

    /* x86 shell code
    unsigned char shellcode[] = {
    0x68, 0x00, 0x00, 0x00, 0x00, // push remotePath
    0xE8, 0x00, 0x00, 0x00, 0x00, // call LoadLibraryA (relative offset)
    0xC3                          // ret
    };
    */

    // Patch the addresses into the shellcode bytes
    *reinterpret_cast<LPVOID *>(&shellcode[6]) = remotePath;
    *reinterpret_cast<LPVOID *>(&shellcode[16]) = loadLibAddr;

    // 4. Allocate and Write the Shellcode (must be EXECUTE_READ)
    LPVOID remoteCode = VirtualAllocEx(hProc, nullptr, sizeof(shellcode), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    WriteProcessMemory(hProc, remoteCode, shellcode, sizeof(shellcode), nullptr);

    // 5. Execute the Shellcode
    HANDLE hThread = CreateRemoteThread(hProc, nullptr, 0, (LPTHREAD_START_ROUTINE)remoteCode, nullptr, 0, nullptr);

    if (hThread) {
        WaitForSingleObject(hThread, INFINITE);
        CloseHandle(hThread);
    }

    // Cleanup
    VirtualFreeEx(hProc, remotePath, 0, MEM_RELEASE);
    VirtualFreeEx(hProc, remoteCode, 0, MEM_RELEASE);
    CloseHandle(hProc);

    return hThread != nullptr;
}


// ── Injection ─────────────────────────────────────────────────────────────────

bool Inject::injectIntoProcess(DWORD targetPid)
{
    

    if (targetPid == 0 || targetPid == 4 || m_dllPath.empty()) {
        std::cerr << "[Inject] Error: Invalid  process ID and/or path: \n ";
        return false;
    }

    if (!std::filesystem::exists(m_dllPath)) {
        std::cerr << "[Inject] Error: DLL does not exist: " << m_dllPath << '\n';
        return false;
    }
    
    std::cout << "[Inject] targetPID: open -> allocate -> write to memory: " << targetPid << '\n';

    // 1. Resolve LoadLibraryA in our own kernel32 (same address in the target).
    HMODULE hKernel = GetModuleHandleW(L"kernel32.dll");
    LPTHREAD_START_ROUTINE loadLibAddr = reinterpret_cast<LPTHREAD_START_ROUTINE>(GetProcAddress(hKernel, "LoadLibraryW"));

    if (!loadLibAddr) {
        std::cerr << "[Inject] GetProcAddress failed: " << GetLastError() << '\n';
        return false;
    }

    // 2. Open the target process.
    HANDLE hProc = OpenProcess(m_processAccess, FALSE, targetPid);
    if (!hProc) {
        std::cerr << "[Inject] OpenProcess failed: (PID " << targetPid << "): " << GetLastError() << '\n';
        return false;
    }

    // 3. Allocate space for the DLL path string in the target process. +1 for the null terminator.
    // ── Convert path to UTF-16 (correct for Windows APIs)
    std::wstring dllPathW = utf8_to_wide(m_dllPath);
    const size_t bytes = (dllPathW.size() + 1) * sizeof(wchar_t);

    LPVOID remotePath = VirtualAllocEx(hProc, nullptr, bytes, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);

    if (!remotePath) {
        std::cerr << "[Inject] VirtualAllocEx failed: " << GetLastError() << '\n';
        CloseHandle(hProc);
        return false;
    }

    // 4. Write the DLL path into the process.
    if (!WriteProcessMemory(hProc, remotePath, dllPathW.c_str(), bytes, nullptr)) {
        std::cerr << "[Inject] WriteProcessMemory failed: " << GetLastError() << '\n';
        VirtualFreeEx(hProc, remotePath, 0, MEM_RELEASE);
        CloseHandle(hProc);
        return false;
    }

    std::cout << "[Inject] LoadLibraryW addr: " << loadLibAddr << std::endl;

    // 5. Spawn a remote thread that calls LoadLibraryW(remotePath).
    HANDLE hThread = CreateRemoteThread( hProc, nullptr, 0, loadLibAddr, remotePath, 0, nullptr);

    if (!hThread) {
        std::cerr << "[Inject] CreateRemoteThread failed: " << GetLastError() << '\n';
        VirtualFreeEx(hProc, remotePath, 0, MEM_RELEASE);
        CloseHandle(hProc);
        return false;
    }

    // 6. Wait for the remote thread to finish and inspect the exit code.
    WaitForSingleObject(hThread, INFINITE);

    DWORD exitCode = 0;
    GetExitCodeThread(hThread, &exitCode);
    CloseHandle(hThread);

    VirtualFreeEx(hProc, remotePath, 0, MEM_RELEASE);
    CloseHandle(hProc);

    if (!exitCode) {
        std::cerr << "[Inject] LoadLibraryW returned NULL in remote process: " << GetLastError() << '\n';
        return false;
    }

    std::cout << "[Inject] Injection successful into PID: " << targetPid 
        << "(modulehandle: 0x" << std::hex << exitCode << std::dec << ")\n";
    return true;
}

bool Inject::injectIntoProcess(DWORD targetPid, const std::string& dllPath)
{
    if (dllPath.empty()) return false;

    m_dllPath = dllPath;
    return injectIntoProcess(targetPid);
}

} // namespace w32t