#ifndef W32T_NAMEDPIPE_HPP
#define W32T_NAMEDPIPE_HPP

// ─────────────────────────────────────────────────────────────────────────────
//  w32t :: NamedPipe
//
//  Simple synchronous Windows named pipe wrapper.
//  Server side: serverConnect() — CreateNamedPipe + ConnectNamedPipe.
//  Client side: clientOpen()   — WaitNamedPipe + CreateFile.
// ─────────────────────────────────────────────────────────────────────────────

#ifndef WIN32_LEAN_AND_MEAN
#  define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#include <string>
#include <cstdint>

namespace w32t {

class NamedPipe {
public:
    static constexpr DWORD k_bufSize = 4096;

    explicit NamedPipe(const std::string& name);
    ~NamedPipe() noexcept;

    NamedPipe(const NamedPipe&)            = delete;
    NamedPipe& operator=(const NamedPipe&) = delete;

    // ── Server ────────────────────────────────────────────────────────────────
    bool serverConnect() noexcept;

    // ── Client ────────────────────────────────────────────────────────────────
    bool clientOpen() noexcept;

    // ── I/O ───────────────────────────────────────────────────────────────────
    DWORD write(const void* data, DWORD len) noexcept;
    DWORD read (void* buf,        DWORD len) noexcept;

    void  disconnect() noexcept;
    void  close()      noexcept;

    [[nodiscard]] bool  valid()     const noexcept { return m_handle != INVALID_HANDLE_VALUE; }
    [[nodiscard]] DWORD lastError() const noexcept { return m_lastErr; }

private:
    std::string m_pipeName;
    HANDLE      m_handle   = INVALID_HANDLE_VALUE;
    DWORD       m_lastErr  = 0;
};

} // namespace w32t

#endif // W32T_NAMEDPIPE_HPP