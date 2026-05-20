#include <win32tools/Network/NamedPipe.hpp>

namespace w32t {

NamedPipe::NamedPipe(const std::string& name)
    : m_pipeName("\\\\.\\pipe\\" + name) {}

NamedPipe::~NamedPipe() noexcept { close(); }

bool NamedPipe::serverConnect() noexcept
{
    m_handle = CreateNamedPipeA(
        m_pipeName.c_str(),
        PIPE_ACCESS_DUPLEX,
        PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
        1, k_bufSize, k_bufSize, 0, nullptr);

    if (m_handle == INVALID_HANDLE_VALUE) {
        m_lastErr = GetLastError();
        return false;
    }
    if (!ConnectNamedPipe(m_handle, nullptr)) {
        DWORD err = GetLastError();
        if (err != ERROR_PIPE_CONNECTED) {
            m_lastErr = err;
            CloseHandle(m_handle);
            m_handle = INVALID_HANDLE_VALUE;
            return false;
        }
    }
    return true;
}

bool NamedPipe::clientOpen() noexcept
{
    // Wait up to 5 seconds for the server to create the pipe.
    if (!WaitNamedPipeA(m_pipeName.c_str(), 5000)) {
        m_lastErr = GetLastError();
        return false;
    }
    m_handle = CreateFileA(
        m_pipeName.c_str(),
        GENERIC_READ | GENERIC_WRITE,
        0, nullptr, OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL, nullptr);

    if (m_handle == INVALID_HANDLE_VALUE) {
        m_lastErr = GetLastError();
        return false;
    }
    return true;
}

DWORD NamedPipe::write(const void* data, DWORD len) noexcept
{
    if (!valid()) return 0;
    DWORD written = 0;
    if (!WriteFile(m_handle, data, len, &written, nullptr))
        m_lastErr = GetLastError();
    return written;
}

DWORD NamedPipe::read(void* buf, DWORD len) noexcept
{
    if (!valid()) return 0;
    DWORD nRead = 0;
    if (!ReadFile(m_handle, buf, len, &nRead, nullptr))
        m_lastErr = GetLastError();
    return nRead;
}

void NamedPipe::disconnect() noexcept
{
    if (valid()) DisconnectNamedPipe(m_handle);
}

void NamedPipe::close() noexcept
{
    if (valid()) {
        CloseHandle(m_handle);
        m_handle = INVALID_HANDLE_VALUE;
    }
}

} // namespace w32t