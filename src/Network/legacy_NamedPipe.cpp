#include <win32tools/Network/NamedPipe.hpp>

namespace w32t {

    NamedPipe::NamedPipe(const std::string &pipeName)
        : m_connected(false)
        , m_bytesRead(0)
        , m_bytesWritten(0)
        , m_bufferSize(k_defaultBufferSize)
        , m_pipeMode(k_defaultPipeMode)
        , m_lastError(0)
        , m_pipeName(pipeName.empty()
            ? "\\\\.\\pipe\\nPipe"
            : ("\\\\.\\pipe\\" + pipeName))
        , m_pipe(CreateNamedPipeA(m_pipeName.c_str(),
            PIPE_ACCESS_DUPLEX,
            m_pipeMode,
            PIPE_UNLIMITED_INSTANCES,
            m_bufferSize,
            m_bufferSize,
            0,
            nullptr))
    {
        if (m_pipe == INVALID_HANDLE_VALUE)
            m_lastError = ::GetLastError();
    }

    NamedPipe::~NamedPipe()
    {
        close();
    }

    // ── Server-side ───────────────────────────────────────────────────────────────

    bool NamedPipe::serverConnect()
    {
        if (m_pipe == INVALID_HANDLE_VALUE)
            return false;

        // Disconnect any stale client before waiting for a new one.
        if (m_connected)
            serverDisconnect();

        const BOOL ok = ::ConnectNamedPipe(m_pipe, nullptr);
        m_connected = (ok != FALSE);
        return m_connected;
    }

    void NamedPipe::serverDisconnect()
    {
        if (m_connected) {
            ::DisconnectNamedPipe(m_pipe);
            m_connected = false;
        }
    }

    // ── Client-side ───────────────────────────────────────────────────────────────

    bool NamedPipe::clientOpen()
    {
        // Retry loop: if the pipe is busy, wait up to 10 s before giving up.
        while (true) {
            m_pipe = ::CreateFileA(m_pipeName.c_str(),
                GENERIC_READ | GENERIC_WRITE,
                0, nullptr,
                OPEN_EXISTING, 0, nullptr);

            m_lastError = ::GetLastError();

            if (m_pipe != INVALID_HANDLE_VALUE)
                return true; // Connected.

            if (m_lastError != ERROR_PIPE_BUSY)
                return false; // Hard failure.

            // Pipe is busy – wait up to 10 seconds for a free instance.
            if (!::WaitNamedPipeA(m_pipeName.c_str(), 10'000)) {
                m_lastError = ::GetLastError();
                return false;
            }
        }
    }

    // ── I/O ───────────────────────────────────────────────────────────────────────

    unsigned long NamedPipe::read(void *outBuffer, unsigned long size)
    {
        // m_connected is only set by serverConnect().
        // Client-side pipes (opened via clientOpen()) are valid with just a handle.
        if (m_pipe == INVALID_HANDLE_VALUE)
            return 0;

        m_bytesRead = 0;
        BOOL ok = ::ReadFile(m_pipe, outBuffer, size, &m_bytesRead, nullptr);

        if (!ok || m_bytesRead == 0) {
            m_lastError = ::GetLastError();
            return 0;
        }
        return m_bytesRead;
    }

    unsigned long NamedPipe::write(const void *inBuffer, unsigned long size)
    {
        if (m_pipe == INVALID_HANDLE_VALUE)
            return 0;

        m_bytesWritten = 0;
        BOOL ok = ::WriteFile(m_pipe, inBuffer, size, &m_bytesWritten, nullptr);

        if (!ok || m_bytesWritten == 0) {
            m_lastError = ::GetLastError();
            return 0;
        }
        return m_bytesWritten;
    }

    // ── Private ───────────────────────────────────────────────────────────────────

    void NamedPipe::close()
    {
        if (m_connected)
            serverDisconnect();

        m_bytesRead = m_bytesWritten = 0;

        if (m_pipe != INVALID_HANDLE_VALUE) {
            ::CloseHandle(m_pipe);
            m_pipe = INVALID_HANDLE_VALUE;
        }
    }

} // namespace w32t