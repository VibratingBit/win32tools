#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <windows.h>

#include <string>

namespace w32t {

/// @brief RAII wrapper around a Win32 named pipe.
///
/// Supports both server mode (CreateNamedPipe → ConnectNamedPipe) and
/// client mode (CreateFile → pOpen). The destructor always disconnects
/// and closes the pipe handle.
///
/// ### Server usage
/// @code
///   w32t::NamedPipe pipe("MyPipe");
///   pipe.serverConnect();
///   char buf[256];
///   pipe.read(buf, sizeof(buf));
///   pipe.write("ack", 3);
/// @endcode
///
/// ### Client usage
/// @code
///   w32t::NamedPipe pipe("MyPipe");
///   pipe.clientOpen();
///   pipe.write("hello", 5);
/// @endcode
class NamedPipe {
public:
    static constexpr DWORD k_defaultBufferSize = 524;
    static constexpr DWORD k_defaultPipeMode   =
        PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT;

    /// @param pipeName  Logical name for the pipe (the prefix \\\\.\\pipe\\ is
    ///                  prepended automatically). Defaults to "nPipe".
    explicit NamedPipe(const std::string& pipeName = {});
    ~NamedPipe();

    // Non-copyable: wraps an OS HANDLE.
    NamedPipe(const NamedPipe&)            = delete;
    NamedPipe& operator=(const NamedPipe&) = delete;

    // ── Server-side ──────────────────────────────────────────────────────────

    /// @brief Block until a client connects (server mode).
    /// @return true on success.
    bool serverConnect();

    /// @brief Disconnect the current client without closing the pipe.
    void serverDisconnect();

    // ── Client-side ──────────────────────────────────────────────────────────

    /// @brief Open an existing named pipe as a client (CreateFile).
    /// @return true on success.
    bool clientOpen();

    // ── I/O ──────────────────────────────────────────────────────────────────

    /// @brief Read up to @p size bytes into @p outBuffer.
    /// @return Bytes read, or 0 on failure / disconnection.
    unsigned long read(void* outBuffer, unsigned long size);

    /// @brief Write @p size bytes from @p inBuffer.
    /// @return Bytes written, or 0 on failure.
    unsigned long write(const void* inBuffer, unsigned long size);

    // ── State ────────────────────────────────────────────────────────────────

    [[nodiscard]] bool   isConnected()    const noexcept { return m_connected; }
    [[nodiscard]] DWORD  lastError()      const noexcept { return m_lastError;  }
    [[nodiscard]] HANDLE nativeHandle()   const noexcept { return m_pipe;       }

private:
    void close();

    bool        m_connected;
    unsigned long m_bytesRead;
    unsigned long m_bytesWritten;
    DWORD       m_bufferSize;
    DWORD       m_pipeMode;
    DWORD       m_lastError;
    std::string m_pipeName;   ///< Full UNC path, e.g. "\\\\.\pipe\\MyPipe".
    HANDLE      m_pipe;
};

} // namespace w32t
