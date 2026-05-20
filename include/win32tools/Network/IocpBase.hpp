#ifndef W32T_IOCPBASE_HPP
#define W32T_IOCPBASE_HPP

// ─────────────────────────────────────────────────────────────────────────────
//  w32t :: IocpBase  (internal shared infrastructure)
//
//  Rules that keep MSVC happy:
//   • __declspec(align(N)) goes INSIDE the struct keyword:
//       struct __declspec(align(16)) Foo { ... };
//   • In-class brace-init on OVERLAPPED/WSABUF/SLIST_ENTRY uses = {}
//     not {}, which some MSVC versions reject on non-aggregate members.
//   • No forward declarations of classes defined in other headers here.
//     UdpRecvOp (which needs IocpUdpServer*) lives in IocpUdpServer.hpp,
//     not here, avoiding the circular-include / incomplete-type errors.
// ─────────────────────────────────────────────────────────────────────────────

#ifndef WIN32_LEAN_AND_MEAN
#  define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#  define NOMINMAX
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>

#include <cstddef>
#include <cstdint>
#include <cstring>

#include <new>

namespace w32t {

    // ── Constants ─────────────────────────────────────────────────────────────────

    inline constexpr std::size_t kRecvBufSize = 4096;
    inline constexpr std::size_t kStagingSize = kRecvBufSize * 2;
    inline constexpr std::size_t kMaxPayload = kRecvBufSize - 4;
    inline constexpr std::size_t kPoolInitial = 128;
    inline constexpr DWORD       kIdleTimeoutMs = 300000UL;
    inline constexpr DWORD       kIdleCheckMs = 10000UL;

    // ── Operation type tags ───────────────────────────────────────────────────────

    enum class IocpOpType : std::uint8_t {
        Recv = 0,
        Send = 1,
        RecvFrom = 2,   // UDP
        SendTo = 3,   // UDP
    };

    // ── IocpOp: OVERLAPPED wrapper ────────────────────────────────────────────────
    // OVERLAPPED MUST be the first member; a pointer to IocpOp is
    // cast-compatible with OVERLAPPED* (standard-layout guarantee).

    struct IocpOp {
        OVERLAPPED  ov;             // MUST stay first — zero in ctor
        IocpOpType  type;

        IocpOp() : type(IocpOpType::Recv) { std::memset(&ov, 0, sizeof(ov)); }
    };

    struct IoContext {
        OVERLAPPED ov;              // MUST stay first
        IocpOpType type;
        char       buffer[kRecvBufSize];
        WSABUF     wsa;

        IoContext() : type(IocpOpType::Recv)
        {
            std::memset(&ov, 0, sizeof(ov));
            std::memset(buffer, 0, sizeof(buffer));
            std::memset(&wsa, 0, sizeof(wsa));
        }
    };

    // ── SendReq: aligned pool node ────────────────────────────────────────────────
    // 16-byte alignment is required by SLIST_ENTRY on x64.
    // __declspec(align(N)) must appear between 'struct' and the tag name.

#pragma warning(push)
#pragma warning(disable : 4324)
    struct __declspec(align(16)) SendReq {
        SLIST_ENTRY entry;          // pool linkage — MUST stay first
        IocpOp      op{};
        WSABUF      wsa{};
        char        data[kRecvBufSize]{};

        SendReq()
        {
            std::memset(&entry, 0, sizeof(entry));
            std::memset(&wsa, 0, sizeof(wsa));
            std::memset(data, 0, sizeof(data));
        }
    };
#pragma warning(pop)

    static_assert(offsetof(SendReq, entry) == 0,
        "SLIST_ENTRY must be the first member of SendReq");
    static_assert(offsetof(IocpOp, ov) == 0,
        "OVERLAPPED must be the first member of IocpOp");

    // ── Protocol framing ──────────────────────────────────────────────────────────

    enum class NetProtocol : std::uint8_t {
        Unknown = 0,
        Packet,     // binary: 4-byte LE length prefix
        Telnet,     // text:   newline-delimited
    };

    inline NetProtocol detectProtocol(std::uint8_t firstByte) noexcept
    {
        return (firstByte >= 0x20 && firstByte <= 0x7E)
            ? NetProtocol::Telnet
            : NetProtocol::Packet;
    }

    // ── SLIST pool helpers ────────────────────────────────────────────────────────

    inline void pool_init(SLIST_HEADER &hdr, std::size_t n)
    {
        InitializeSListHead(&hdr);
        for (std::size_t i = 0; i < n; ++i) {
            SendReq *r = static_cast<SendReq *>(_aligned_malloc(sizeof(SendReq), 16));
            if (r) { new(r) SendReq(); InterlockedPushEntrySList(&hdr, &r->entry); }
        }
    }

    inline void pool_drain(SLIST_HEADER &hdr)
    {
        PSLIST_ENTRY e;
        while ((e = InterlockedPopEntrySList(&hdr)) != nullptr)
            _aligned_free(e);
    }

    inline SendReq *pool_acquire(SLIST_HEADER &hdr)
    {
        PSLIST_ENTRY e = InterlockedPopEntrySList(&hdr);
        if (e) return reinterpret_cast<SendReq *>(e);
        SendReq *r = static_cast<SendReq *>(_aligned_malloc(sizeof(SendReq), 16));
        if (r) new(r) SendReq();
        return r;
    }

    inline void pool_release(SLIST_HEADER &hdr, SendReq *r)
    {
        if (r) InterlockedPushEntrySList(&hdr, &r->entry);
    }

} // namespace w32t

#endif // W32T_IOCPBASE_HPP