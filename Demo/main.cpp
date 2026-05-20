// =============================================================================
//  win32tools v2.0 — Comprehensive Demo & Integration Test
//
//  Tests (in order):
//    1.  Core            — process discovery, byte helpers
//    2.  DriveInfo       — HDD serials, MAC, HWID
//    3.  Scanner v2      — BMH, scan_all, scan_multi, self-scan
//    4.  HaxHelper       — self-dump, IDA sig, findExternalBytes
//    5.  Packet          — serialisation round-trip, all types
//    6.  NamedPipe       — server/client intra-process
//    7.  NetworkSocket   — sync TCP loopback with Packet framing
//    8.  IocpTcpServer + IocpTcpClient  — async TCP with broadcast
//    9.  IocpUdpServer + IocpUdpClient  — async UDP connected + unconnected
//   10.  Inject          — self-inject version.dll + post-inject scan
// =============================================================================
#ifndef WIN32_LEAN_AND_MEAN
#  define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#  define NOMINMAX
#endif

#include <windows.h>
#include <psapi.h>
#include <io.h>
#include <fcntl.h>

// ── win32tools ────────────────────────────────────────────────────────────────
#include <win32tools/Tools/Core.hpp>
#include <win32tools/Tools/DriveInfo.hpp>
#include <win32tools/Tools/HaxHelper.hpp>
#include <win32tools/Tools/Inject.hpp>
#include <win32tools/Tools/scanner.hpp>

#include <win32tools/Network/Socket.hpp>
#include <win32tools/Network/Packet.hpp>
#include <win32tools/Network/NetworkSocket.hpp>
#include <win32tools/Network/NamedPipe.hpp>
#include <win32tools/Network/IocpTcpServer.hpp>
#include <win32tools/Network/IocpTcpClient.hpp>
#include <win32tools/Network/IocpUdpServer.hpp>
#include <win32tools/Network/IocpUdpClient.hpp>

#include <atomic>
#include <chrono>
#include <iostream>
#include <limits>
#include <mutex>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

// =============================================================================
//  UI helpers
// =============================================================================

static std::string repeat(const std::string &s, int n)
{
    std::string r; r.reserve(s.size() * static_cast<std::size_t>(n));
    for (int i = 0; i < n; ++i) r += s;
    return r;
}

static void setupConsole()
{
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);
    HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
    if (h != INVALID_HANDLE_VALUE) {
        DWORD m = 0;
        if (GetConsoleMode(h, &m))
            SetConsoleMode(h, m | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
    }
}

// All UI functions are plain static (not in anonymous namespace) to avoid
// MSVC name-lookup ambiguity with member functions named "result" etc.
static const std::string kLine = repeat("\xe2\x94\x80", 56);

static void ui_section(const std::string &t)
{
    std::cout << "\n\xe2\x94\x8c" << kLine << "\xe2\x94\x90\n"
        << "\xe2\x94\x82  " << t << "\n"
        << "\xe2\x94\x94" << kLine << "\xe2\x94\x98\n";
}
static void ui_ok(const std::string &s) { std::cout << "  \xe2\x9c\x94  " << s << "\n"; }
static void ui_fail(const std::string &s) { std::cout << "  \xe2\x9c\x98  " << s << "\n"; }
static void ui_info(const std::string &s) { std::cout << "  \xe2\x80\xa2  " << s << "\n"; }
static void ui_warn(const std::string &s) { std::cout << "  \xe2\x9a\xa0  " << s << "\n"; }

static void ui_result(const std::string &label, bool pass)
{
    if (pass) ui_ok(label + "  ->  PASS");
    else      ui_fail(label + "  ->  FAIL");
}

static std::string to_hex(std::uintptr_t v)
{
    std::ostringstream ss;
    ss << "0x" << std::hex << std::uppercase << v;
    return ss.str();
}

// Small helper: wait up to timeoutMs for a condition, polling every 10 ms.
static bool wait_for(std::atomic<int> &flag, int expected, DWORD timeoutMs)
{
    DWORD elapsed = 0;
    while (elapsed < timeoutMs) {
        if (flag.load() == expected) return true;
        Sleep(10);
        elapsed += 10;
    }
    return flag.load() == expected;
}

// =============================================================================
//  1. Core
// =============================================================================
static void demo_Core()
{
    ui_section("1. Core - Process Discovery & Byte Helpers");

    // processIdFromExe
    DWORD wPid = w32t::Core::processIdFromExe("windhawk.exe");
    if (wPid) std::cout << "  \xe2\x9c\x94  windhawk.exe PID = " << wPid << '\n';
    else      ui_warn("windhawk.exe not found (optional target)");

    // processIdListFromExe
    auto svcs = w32t::Core::processIdListFromExe("svchost.exe");
    ui_result("svchost.exe instance count > 0", !svcs.empty());
    std::cout << "       count = " << svcs.size() << '\n';

    // processIdFromWindow
    DWORD tpid = w32t::Core::processIdFromWindow("", "Shell_TrayWnd");
    if (tpid) ui_ok("Shell_TrayWnd PID = " + std::to_string(tpid));
    else      ui_warn("Shell_TrayWnd not found (headless/no desktop)");

    // getInternalModuleInfo
    auto mi = w32t::Core::getInternalModuleInfo("kernel32.dll");
    ui_result("getInternalModuleInfo(kernel32.dll)", mi != nullptr);
    if (mi != nullptr)
        std::cout << "       base=" << to_hex(reinterpret_cast<uintptr_t>(mi->lpBaseOfDll))
        << "  size=" << mi->SizeOfImage << " bytes\n";

    // getModuleFromPid — self
    DWORD selfPid = GetCurrentProcessId();
    char selfPath[MAX_PATH]{};
    GetModuleFileNameA(nullptr, selfPath, MAX_PATH);
    std::string selfExe = selfPath;
    auto sl = selfExe.find_last_of("\\/");
    if (sl != std::string::npos) selfExe = selfExe.substr(sl + 1);

    auto selfMod = w32t::Core::getModuleFromPid(selfPid, selfExe);
    ui_result("getModuleFromPid(self)", selfMod != nullptr);

    // toBytes / appendBytes
    auto bytes = w32t::Core::toBytes(0xDEADBEEFu);
    ui_result("toBytes(0xDEADBEEF) size == 4", bytes.size() == 4);
    std::cout << "       bytes = ";
    for (auto b : bytes) std::cout << std::hex << static_cast<int>(b) << ' ';
    std::cout << std::dec << '\n';

    std::vector<std::uint8_t> buf;
    w32t::Core::appendBytes(buf, 0xCAFEBABEu);
    w32t::Core::appendBytes(buf, "win32tools", 10);
    ui_result("appendBytes total == 14", buf.size() == 14);
}

// =============================================================================
//  2. DriveInfo
// =============================================================================
static void demo_DriveInfo()
{
    ui_section("2. DriveInfo - Hardware ID");

    w32t::DriveInfo di;
    int found = 0;
    for (int i = 0; i < 4; ++i) {
        std::string path = "\\\\.\\PhysicalDrive" + std::to_string(i);
        HANDLE h = CreateFileA(path.c_str(),
            GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE,
            nullptr, OPEN_EXISTING, 0, nullptr);
        if (h == INVALID_HANDLE_VALUE) {
            DWORD e = GetLastError();
            if (e == ERROR_FILE_NOT_FOUND || e == ERROR_PATH_NOT_FOUND) break;
            continue;
        }
        CloseHandle(h);
        ++found;
        std::string serial = di.hddSerial();
        std::cout << "  \xe2\x80\xa2  Drive" << i << " serial = ["
            << (serial.empty() ? "(unavailable)" : serial) << "]\n";
    }
    if (!found) ui_warn("No drives accessible — run as Administrator");

    std::string mac = di.macAddress();
    std::string mobo = di.getMoboSerial();
    if (!mac.empty()) ui_ok("MAC = " + mac);
    else              ui_warn("MAC unavailable");

    if (!mac.empty() && !di.getSerials().empty()) {
        std::string hwid = w32t::DriveInfo::buildHwid(
            di.getSerials()[0] + mobo, mac);
        ui_ok("HWID = " + hwid);
    }
}

// =============================================================================
//  3. Scanner v2
// =============================================================================

// Known blob — offsets are asserted below.
static const std::uint8_t k_blob[] = {
    0x00, 0x01, 0x02, 0x03,
    0x48, 0x8B, 0x05, 0xAA, 0xBB,   // offset 4  — sig A: 48 8B 05 ?? ??
    0x00, 0x00, 0x00,
    0xDE, 0xAD, 0xBE, 0xEF,          // offset 12 — sig B: DE AD BE EF
    0xFF, 0xFF,
    0x48, 0x8B, 0x05, 0xCC, 0xDD,   // offset 18 — sig A (2nd)
    0xDE, 0xAD, 0xBE, 0xEF,          // offset 23 — sig B (2nd)
    0x90, 0x90, 0x90
};

static void demo_Scanner()
{
    ui_section("3. Scanner v2 - Full API Self-Test");

    // 3a. IDA pattern
    {
        ui_info("3a. IDA  \"48 8B 05 ?? ??\"");
        w32t::PatternOwned owned = w32t::PatternOwned::from_ida("48 8B 05 ?? ??");
        ui_result("PatternOwned::valid()", owned.valid());
        if (owned.valid()) {
            const std::uint8_t *hit = w32t::scan_region(k_blob, sizeof(k_blob), owned.get());
            ui_result("scan_region IDA hit at offset 4",
                hit && (hit - k_blob) == 4);
        }
    }

    // 3b. char-mask pattern
    {
        ui_info("3b. char-mask  {DE AD BE EF}  \"xxxx\"");
        const std::uint8_t pb[] = { 0xDE, 0xAD, 0xBE, 0xEF };
        w32t::Pattern pat{};
        w32t::Pattern::from_char_mask(pb, "xxxx", pat);
        const std::uint8_t *hit = w32t::scan_region(k_blob, sizeof(k_blob), pat);
        ui_result("scan_region char-mask hit at offset 12",
            hit && (hit - k_blob) == 12);
    }

    // 3c. scan_all
    {
        ui_info("3c. scan_all — all occurrences of sig A");
        w32t::PatternOwned owned = w32t::PatternOwned::from_ida("48 8B 05 ?? ??");
        if (owned.valid()) {
            std::uintptr_t results[8]{};
            std::size_t cnt = w32t::scan_all(
                reinterpret_cast<std::uintptr_t>(k_blob),
                reinterpret_cast<std::uintptr_t>(k_blob + sizeof(k_blob)),
                owned.get(), results, 8);
            ui_result("scan_all count == 2", cnt == 2);
            for (std::size_t i = 0; i < cnt; ++i)
                std::cout << "       match[" << i << "] offset="
                << (results[i] - reinterpret_cast<std::uintptr_t>(k_blob)) << '\n';
        }
    }

    // 3d. scan_multi
    {
        ui_info("3d. scan_multi — sig A + sig B in one walk");
        w32t::PatternOwned a = w32t::PatternOwned::from_ida("48 8B 05 ?? ??");
        w32t::PatternOwned b = w32t::PatternOwned::from_ida("DE AD BE EF");
        if (a.valid() && b.valid()) {
            w32t::Pattern  pats[2] = { a.get(), b.get() };
            std::uintptr_t results[2] = {};
            std::size_t nf = w32t::scan_multi(
                reinterpret_cast<std::uintptr_t>(k_blob),
                reinterpret_cast<std::uintptr_t>(k_blob + sizeof(k_blob)),
                pats, results, 2);
            ui_result("scan_multi found == 2", nf == 2);
            if (nf == 2) {
                std::size_t offA = results[0] - reinterpret_cast<std::uintptr_t>(k_blob);
                std::size_t offB = results[1] - reinterpret_cast<std::uintptr_t>(k_blob);
                ui_result("sig A offset == 4", offA == 4);
                ui_result("sig B offset == 12", offB == 12);
            }
        }
    }

    // 3e. wildcard-first slow path
    {
        ui_info("3e. Wildcard-first  \"?? 8B 05\"");
        w32t::PatternOwned owned = w32t::PatternOwned::from_ida("?? 8B 05");
        if (owned.valid()) {
            const std::uint8_t *hit = w32t::scan_region(k_blob, sizeof(k_blob), owned.get());
            ui_result("wildcard-first offset == 4", hit && (hit - k_blob) == 4);
        }
    }

    // 3f. alignment
    {
        ui_info("3f. Alignment constraints");
        const std::uint8_t pb[] = { 0xDE, 0xAD, 0xBE, 0xEF };
        w32t::Pattern pat{};
        w32t::Pattern::from_char_mask(pb, "xxxx", pat);
        const std::uint8_t *h4 = w32t::scan_region(k_blob, sizeof(k_blob), pat, 4);
        const std::uint8_t *h8 = w32t::scan_region(k_blob, sizeof(k_blob), pat, 8);
        ui_result("align=4 finds offset 12", h4 && (h4 - k_blob) == 12);
        ui_result("align=8 misses offset 12 (not 8-byte aligned)", h8 == nullptr);
    }

    // 3g. edge cases
    {
        ui_info("3g. Edge cases");
        w32t::Pattern empty{};
        w32t::PatternOwned owned = w32t::PatternOwned::from_ida("48 8B 05 ?? ??");
        ui_result("empty pattern -> null",
            w32t::scan_region(k_blob, sizeof(k_blob), empty) == nullptr);
        ui_result("size < pat.len -> null",
            w32t::scan_region(k_blob, 2, owned.get()) == nullptr);
        ui_result("null base -> null",
            w32t::scan_region(nullptr, sizeof(k_blob), owned.get()) == nullptr);
    }

    // 3h. live self-scan
    {
        ui_info("3h. Live self-scan via VirtualQuery");
        static volatile std::uint8_t sentinel[8] = {
            0x57, 0x33, 0x72, 0x6B, 0x5F, 0x4C, 0x49, 0x56
        };
        (void)sentinel[0];
        const std::uint8_t pb[8] = { 0x57, 0x33, 0x72, 0x6B, 0x5F, 0x4C, 0x49, 0x56 };
        w32t::Pattern pat{};
        w32t::Pattern::from_char_mask(pb, "xxxxxxxx", pat);

        HMODULE self = GetModuleHandleA(nullptr);
        auto *base = reinterpret_cast<const std::uint8_t *>(self);
        auto *dos = reinterpret_cast<const IMAGE_DOS_HEADER *>(base);
        auto *nt = reinterpret_cast<const IMAGE_NT_HEADERS *>(base + dos->e_lfanew);
        std::size_t imgSize = nt->OptionalHeader.SizeOfImage;

        std::uintptr_t hit = w32t::scan(
            reinterpret_cast<std::uintptr_t>(base),
            reinterpret_cast<std::uintptr_t>(base + imgSize), pat);
        ui_result("scan() found sentinel in own image", hit != 0);
        if (hit) std::cout << "       sentinel at " << to_hex(hit) << '\n';

        std::uintptr_t all[4]{};
        std::size_t cnt = w32t::scan_all(
            reinterpret_cast<std::uintptr_t>(base),
            reinterpret_cast<std::uintptr_t>(base + imgSize), pat, all, 4);
        ui_result("scan_all() count >= 1", cnt >= 1);
        std::cout << "       occurrences = " << cnt << '\n';
    }
}

// =============================================================================
//  4. HaxHelper — self-dump
// =============================================================================
static void demo_HaxHelper()
{
    ui_section("4. HaxHelper - Self-Dump & Pattern Scan");

    char selfPath[MAX_PATH]{};
    GetModuleFileNameA(nullptr, selfPath, MAX_PATH);
    std::string selfExe = selfPath;
    auto sl = selfExe.find_last_of("\\/");
    if (sl != std::string::npos) selfExe = selfExe.substr(sl + 1);
    std::cout << "  \xe2\x80\xa2  Self = " << selfExe << '\n';

    w32t::HaxHelper hax(selfExe);

    // dumpMemory — always works without admin on self
    bool dumped = hax.dumpMemory();
    ui_result("dumpMemory(self)", dumped);
    if (!dumped) { ui_warn("Skipping pattern scans"); return; }
    std::cout << "       " << hax.dumpedSize() << " bytes dumped\n";

    DWORD selfPid = GetCurrentProcessId();
    auto mod = w32t::Core::getModuleFromPid(selfPid, selfExe);
    if (mod == nullptr) { ui_warn("getModuleFromPid(self) failed"); return; }

    // MZ header — char-mask
    const std::uint8_t mz[] = { 0x4D, 0x5A };
    std::uintptr_t mzBytes = hax.findExternalBytes(*mod, mz, "xx");
    ui_result("findExternalBytes self MZ", mzBytes != 0);
    if (mzBytes) std::cout << "       MZ at " << to_hex(mzBytes) << '\n';

    // MZ header — IDA overload
    std::uintptr_t mzIda = hax.findExternalIda(*mod, "4D 5A");
    ui_result("findExternalIda  self MZ", mzIda != 0);
    ui_result("both overloads agree", mzBytes == mzIda);

    // invalidate + re-dump
    hax.invalidateDump();
    ui_result("invalidateDump clears isDumped", !hax.isDumped());
    ui_result("re-dump after invalidate", hax.dumpMemory());

    // scan for k_blob sig A bytes in this image
    std::uintptr_t blobHit = hax.findExternalIda(*mod, "48 8B 05 AA BB");
    std::cout << "  \xe2\x80\xa2  k_blob sig A in self: "
        << (blobHit ? to_hex(blobHit) : std::string("(not present after opts)")) << '\n';
}

// =============================================================================
//  5. Packet — all types round-trip
// =============================================================================
static void demo_Packet()
{
    ui_section("5. Packet - Full Type Round-Trip");

    w32t::Packet pkt;
    pkt << static_cast<std::uint8_t> (0xAB);
    pkt << static_cast<std::uint16_t>(0x1234);
    pkt << static_cast<std::uint32_t>(0xDEADBEEF);
    pkt << static_cast<std::uint64_t>(0xCAFEBABEDEAD1234ULL);
    pkt << true;
    pkt << 3.14f;
    pkt << 2.71828;
    pkt << std::string("hello_string");
    pkt << "hello_cstr";
    std::cout << "  \xe2\x80\xa2  Packed size = " << pkt.size() << " bytes\n";

    pkt.pos = 0;
    std::uint8_t  u8{};  pkt >> u8;
    std::uint16_t u16{}; pkt >> u16;
    std::uint32_t u32{}; pkt >> u32;
    std::uint64_t u64{}; pkt >> u64;
    bool          b{};   pkt >> b;
    float         f{};   pkt >> f;
    double        d{};   pkt >> d;
    std::string   str1;  pkt >> str1;
    char          cstr[64]{};  pkt >> cstr;

    ui_result("uint8  0xAB", u8 == 0xAB);
    ui_result("uint16 0x1234", u16 == 0x1234);
    ui_result("uint32 0xDEADBEEF", u32 == 0xDEADBEEF);
    ui_result("uint64 0xCAFEBABEDEAD1234", u64 == 0xCAFEBABEDEAD1234ULL);
    ui_result("bool   true", b == true);
    ui_result("float  3.14f", f > 3.13f && f < 3.15f);
    ui_result("double 2.71828", d > 2.717 && d < 2.720);
    ui_result("string \"hello_string\"", str1 == "hello_string");
    ui_result("cstr   \"hello_cstr\"", std::string(cstr) == "hello_cstr");
}

// =============================================================================
//  6. NamedPipe — full duplex intra-process
// =============================================================================
static void demo_NamedPipe()
{
    ui_section("6. NamedPipe - Bidirectional Server/Client");

    const std::string pipeName = "W32TDemoV2Pipe";
    const std::string ping = "PING_from_client";
    const std::string pong = "PONG_from_server";
    std::string       serverGot, clientGot;
    bool              sOk = false, cOk = false;

    std::thread srv([&]() {
        w32t::NamedPipe server(pipeName);
        if (!server.serverConnect()) return;
        char buf[256]{};
        if (server.read(buf, static_cast<DWORD>(ping.size() + 1)) > 0) {
            serverGot = buf; sOk = true;
        }
        server.write(pong.c_str(), static_cast<DWORD>(pong.size() + 1));
        });
    Sleep(60);
    std::thread cli([&]() {
        w32t::NamedPipe client(pipeName);
        if (!client.clientOpen()) return;
        client.write(ping.c_str(), static_cast<DWORD>(ping.size() + 1));
        char buf[256]{};
        if (client.read(buf, static_cast<DWORD>(pong.size() + 1)) > 0) {
            clientGot = buf; cOk = true;
        }
        });
    srv.join(); cli.join();

    ui_result("Server received PING", sOk && serverGot == ping);
    ui_result("Client received PONG", cOk && clientGot == pong);
}

// =============================================================================
//  7. NetworkSocket — sync TCP with Packet framing
// =============================================================================
static constexpr uint16_t k_tcpSyncPort = 19010;

static void demo_NetworkSocket()
{
    ui_section("7. NetworkSocket - Sync TCP Packet Loopback");

    std::atomic<int> srvReady{ 0 };
    std::string      srvGotStr;
    std::uint32_t    srvGotU32 = 0;

    std::thread srv([&]() {
        w32t::NetworkSocket listener(w32t::Socket::Type::Tcp);
        if (!listener.create()) return;

        SOCKET ls = listener.handle();
        int opt = 1;
        setsockopt(ls, SOL_SOCKET, SO_REUSEADDR,
            reinterpret_cast<const char *>(&opt), sizeof(opt));
        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port = htons(k_tcpSyncPort);
        addr.sin_addr.s_addr = INADDR_ANY;
        ::bind(ls, reinterpret_cast<sockaddr *>(&addr), sizeof(addr));
        ::listen(ls, 1);
        srvReady.store(1);

        SOCKET cs = ::accept(ls, nullptr, nullptr);
        if (cs == INVALID_SOCKET) return;

        w32t::NetworkSocket conn(w32t::Socket::Type::Tcp, cs);
        w32t::Packet in;
        conn.recv(in);
        in >> srvGotStr >> srvGotU32;

        w32t::Packet reply;
        reply << std::string("ACK") << static_cast<std::uint32_t>(0xACACACACu);
        conn.send(reply);
        });

    while (!srvReady.load()) Sleep(5);

    w32t::NetworkSocket client(w32t::Socket::Type::Tcp);
    client.create();
    bool connected = client.connectTo("127.0.0.1", k_tcpSyncPort);
    ui_result("NetworkSocket::connectTo()", connected);

    if (connected) {
        w32t::Packet pkt;
        pkt << std::string("hello_sync_tcp") << static_cast<std::uint32_t>(0xBEEFu);
        int sent = client.send(pkt);
        std::cout << "  \xe2\x80\xa2  Sent " << sent << " bytes\n";

        w32t::Packet reply;
        client.recv(reply);
        std::string ack; std::uint32_t code{};
        reply >> ack >> code;

        ui_result("Server decoded string", srvGotStr == "hello_sync_tcp");
        ui_result("Server decoded uint32", srvGotU32 == 0xBEEFu);
        ui_result("Client got ACK string", ack == "ACK");
        ui_result("Client got ACK code", code == 0xACACACACu);
    }
    srv.join();
}

// =============================================================================
//  8. IocpTcpServer + IocpTcpClient — async IOCP TCP
// =============================================================================
static constexpr uint16_t k_tcpIocpPort = 19011;

static void demo_IocpTcp()
{
    ui_section("8. IocpTcpServer + IocpTcpClient - Async IOCP TCP");

    // ── Shared state ──────────────────────────────────────────────────────────
    std::atomic<int>  srvConnected{ 0 };
    std::atomic<int>  srvDataCount{ 0 };
    std::atomic<int>  clientDataCount{ 0 };
    std::string       srvLastMsg;
    std::string       clientLastMsg;
    std::mutex        mtx;

    // ── Server ────────────────────────────────────────────────────────────────
    w32t::IocpTcpServer server;

    w32t::TcpServerCallbacks scb;
    scb.on_connect = [&](w32t::TcpClientHandle c) {
        c->id = 1;
        srvConnected.fetch_add(1);
        // Send welcome in PACKET mode (first byte is not printable ASCII).
        const char *welcome = "\x01WELCOME";
        server.send(c, welcome, static_cast<int>(strlen(welcome)));
        };
    scb.on_data = [&](w32t::TcpClientHandle c, const char *data, int len) {
        std::lock_guard<std::mutex> lk(mtx);
        srvLastMsg.assign(data, static_cast<std::size_t>(len));
        srvDataCount.fetch_add(1);
        // Echo back with a prefix.
        std::string echo = "ECHO:" + srvLastMsg;
        server.send(c, echo.data(), static_cast<int>(echo.size()));
        };
    scb.on_close = [&](w32t::TcpClientHandle) {};

    bool initOk = server.init(scb, 2);
    ui_result("IocpTcpServer::init()", initOk);
    if (!initOk) return;

    std::thread srvThread([&]() {
        server.listen(k_tcpIocpPort);
        });

    Sleep(80);  // let server bind

    // ── Client ────────────────────────────────────────────────────────────────
    w32t::IocpTcpClient client;

    w32t::TcpClientCallbacks ccb;
    ccb.on_connect = [&]() {};
    ccb.on_data = [&](const char *data, int len) {
        std::lock_guard<std::mutex> lk(mtx);
        clientLastMsg.assign(data, static_cast<std::size_t>(len));
        clientDataCount.fetch_add(1);
        };
    ccb.on_close = [&]() {};

    bool cOk = client.connect("127.0.0.1", k_tcpIocpPort, ccb);
    ui_result("IocpTcpClient::connect()", cOk);
    if (!cOk) { server.stop(); srvThread.join(); return; }

    // Wait for the welcome message.
    bool gotWelcome = wait_for(clientDataCount, 1, 2000);
    ui_result("Client received welcome from server", gotWelcome);

    // Send a message to the server.
    const std::string msg1 = "hello_async_tcp";
    int snd = client.send(msg1.data(), static_cast<int>(msg1.size()));
    ui_result("IocpTcpClient::send()", snd == 0);

    // Wait for server to receive it and echo back.
    bool srvGot = wait_for(srvDataCount, 1, 2000);
    bool cliGot2 = wait_for(clientDataCount, 2, 2000);
    ui_result("Server received client message", srvGot);
    {
        std::lock_guard<std::mutex> lk(mtx);
        ui_result("Server decoded message correctly",
            srvLastMsg == msg1);
        ui_result("Client received echo back",
            cliGot2 && clientLastMsg == "ECHO:" + msg1);
    }

    // ── broadcast test ─────────────────────────────────────────────────────
    // Connect a second client to test broadcast.
    std::atomic<int>  c2DataCount{ 0 };
    std::string       c2LastMsg;
    w32t::IocpTcpClient client2;
    w32t::TcpClientCallbacks ccb2;
    ccb2.on_connect = [&]() {};
    ccb2.on_data = [&](const char *d, int l) {
        std::lock_guard<std::mutex> lk(mtx);
        c2LastMsg.assign(d, static_cast<std::size_t>(l));
        c2DataCount.fetch_add(1);
        };
    ccb2.on_close = [&]() {};

    bool c2Ok = client2.connect("127.0.0.1", k_tcpIocpPort, ccb2);
    ui_result("Second client connected", c2Ok);
    if (c2Ok) {
        Sleep(100); // let server register c2
        const std::string bcast = "BROADCAST_MSG";
        server.broadcast(bcast.data(), static_cast<int>(bcast.size()));

        bool b1 = wait_for(clientDataCount, 3, 2000);
        bool b2 = wait_for(c2DataCount, 2, 2000);
        ui_result("Client 1 received broadcast", b1);
        ui_result("Client 2 received broadcast", b2);
    }

    // ── clientCount ────────────────────────────────────────────────────────
    int cc = server.clientCount();
    std::cout << "  \xe2\x80\xa2  Server clientCount = " << cc << '\n';
    ui_result("clientCount >= 1", cc >= 1);

    // ── findById ───────────────────────────────────────────────────────────
    w32t::TcpClientHandle found = server.findById(1);
    ui_result("findById(1) != null", found != nullptr);

    // ── iterateClients ─────────────────────────────────────────────────────
    int itCount = 0;
    server.iterateClients([&](w32t::TcpClientHandle) { ++itCount; });
    ui_result("iterateClients visits >= 1 client", itCount >= 1);

    client.disconnect();
    client2.disconnect();
    server.stop();
    srvThread.join();
    server.shutdown();
}

// =============================================================================
//  9. IocpUdpServer + IocpUdpClient
// =============================================================================
static constexpr uint16_t k_udpPort = 19020;

static void demo_IocpUdp()
{
    ui_section("9. IocpUdpServer + IocpUdpClient - Async IOCP UDP");

    std::atomic<int>  srvDataCount{ 0 };
    std::atomic<int>  clientDataCount{ 0 };
    std::string       srvLastMsg;
    std::string       clientLastMsg;
    std::mutex        mtx;

    // ── Server ────────────────────────────────────────────────────────────────
    w32t::IocpUdpServer udpSrv(4);

    w32t::UdpServerCallbacks scb;
    scb.on_new_peer = [&](w32t::UdpPeer *p) {
        std::cout << "  \xe2\x80\xa2  New UDP peer: " << p->ip << ":" << p->port
            << " id=" << p->id << '\n';
        };
    scb.on_data = [&](w32t::UdpPeer *peer, const char *data, int len) {
        std::lock_guard<std::mutex> lk(mtx);
        srvLastMsg.assign(data, static_cast<std::size_t>(len));
        srvDataCount.fetch_add(1);
        // Echo back to sender.
        std::string echo = "UDP_ECHO:" + srvLastMsg;
        udpSrv.sendTo(peer, echo.data(), static_cast<int>(echo.size()));
        };
    scb.on_peer_timeout = nullptr;

    bool sOk = udpSrv.init(scb, 2);
    ui_result("IocpUdpServer::init()", sOk);
    if (!sOk) return;

    bool lOk = udpSrv.listen(k_udpPort);
    ui_result("IocpUdpServer::listen()", lOk);
    if (!lOk) { udpSrv.shutdown(); return; }

    std::cout << "  \xe2\x80\xa2  UDP server on port " << udpSrv.boundPort() << '\n';
    Sleep(50);

    // ── Connected UDP client ──────────────────────────────────────────────────
    w32t::IocpUdpClient udpClient;

    w32t::UdpClientCallbacks ccb;
    ccb.on_data = [&](const sockaddr_storage &, const char *d, int l) {
        std::lock_guard<std::mutex> lk(mtx);
        clientLastMsg.assign(d, static_cast<std::size_t>(l));
        clientDataCount.fetch_add(1);
        };
    ccb.on_close = [&]() {};

    bool cOk = udpClient.connectTo("127.0.0.1", k_udpPort, ccb);
    ui_result("IocpUdpClient::connectTo()", cOk);
    if (!cOk) { udpSrv.shutdown(); return; }

    std::cout << "  \xe2\x80\xa2  UDP client local port = " << udpClient.localPort() << '\n';

    // Send datagram 1.
    const std::string msg1 = "udp_msg_one";
    udpClient.send(msg1.data(), static_cast<int>(msg1.size()));
    bool s1 = wait_for(srvDataCount, 1, 2000);
    bool r1 = wait_for(clientDataCount, 1, 2000);
    ui_result("Server received UDP datagram", s1);
    {
        std::lock_guard<std::mutex> lk(mtx);
        ui_result("Server decoded message correctly", srvLastMsg == msg1);
    }
    ui_result("Client received UDP echo", r1);
    {
        std::lock_guard<std::mutex> lk(mtx);
        ui_result("Echo content correct",
            clientLastMsg == "UDP_ECHO:" + msg1);
    }

    // Send datagram 2 — verify peerCount.
    const std::string msg2 = "udp_msg_two";
    udpClient.send(msg2.data(), static_cast<int>(msg2.size()));
    wait_for(srvDataCount, 2, 2000);

    int pc = udpSrv.peerCount();
    std::cout << "  \xe2\x80\xa2  Peer count = " << pc << '\n';
    ui_result("peerCount >= 1", pc >= 1);

    // ── Unconnected client + broadcast ────────────────────────────────────────
    w32t::IocpUdpClient udpClient2;
    std::atomic<int>  c2Count{ 0 };
    std::string       c2Msg;
    w32t::UdpClientCallbacks ccb2;
    ccb2.on_data = [&](const sockaddr_storage &, const char *d, int l) {
        std::lock_guard<std::mutex> lk(mtx);
        c2Msg.assign(d, static_cast<std::size_t>(l));
        c2Count.fetch_add(1);
        };
    ccb2.on_close = [&]() {};

    bool c2Ok = udpClient2.bind(0, ccb2);   // unconnected, OS assigns port
    ui_result("Second UDP client bind(0)", c2Ok);
    if (c2Ok) {
        // Send from unconnected client by building address manually.
        sockaddr_in dest{};
        dest.sin_family = AF_INET;
        dest.sin_port = htons(k_udpPort);
        inet_pton(AF_INET, "127.0.0.1", &dest.sin_addr);
        sockaddr_storage destSS{};
        std::memcpy(&destSS, &dest, sizeof(dest));
        destSS.ss_family = AF_INET;

        const std::string msg3 = "udp_unconnected";
        udpClient2.sendTo(destSS, msg3.data(), static_cast<int>(msg3.size()));
        wait_for(srvDataCount, 3, 2000);
        // Server now knows 2 peers; broadcast to both.
        Sleep(50);
        const std::string bcast = "UDP_BROADCAST";
        udpSrv.broadcast(bcast.data(), static_cast<int>(bcast.size()));

        bool b1 = wait_for(clientDataCount, 2, 2000);
        bool b2 = wait_for(c2Count, 1, 2000);
        ui_result("Client 1 received UDP broadcast", b1);
        ui_result("Client 2 received UDP broadcast", b2);

        // findPeer by IP+port
        w32t::UdpPeer *fp = udpSrv.findPeerById(1);
        ui_result("findPeerById(1) != null", fp != nullptr);

        udpClient2.disconnect();
    }

    udpClient.disconnect();
    udpSrv.shutdown();
}

// =============================================================================
//  10. Inject — self-inject + post-inject scan
// =============================================================================
static void demo_Inject()
{
    ui_section("10. Inject - Self-Inject version.dll + Post-Inject Scan");

    w32t::Inject injector;
    injector.setDllPath("C:\\Windows\\System32\\version.dll");
    std::cout << "  \xe2\x80\xa2  DLL = " << injector.dllPath() << '\n';

    DWORD selfPid = GetCurrentProcessId();

    if (GetModuleHandleA("version.dll")) {
        ui_ok("version.dll already loaded (prior run)");
    }
    else {
        bool ok = injector.injectIntoProcess(selfPid);
        ui_result("injectIntoProcess(self)", ok);

        if (ok) {
            HMODULE hVer = GetModuleHandleA("version.dll");
            std::cout << "  \xe2\x9c\x94  Module handle = "
                << to_hex(reinterpret_cast<std::uintptr_t>(hVer)) << '\n';

            // Post-inject: scan version.dll for its MZ header using scan().
            MODULEINFO mi{};
            GetModuleInformation(GetCurrentProcess(), hVer, &mi, sizeof(mi));

            const std::uint8_t mzb[] = { 0x4D, 0x5A };
            w32t::Pattern mzPat{};
            w32t::Pattern::from_char_mask(mzb, "xx", mzPat);

            std::uintptr_t mzHit = w32t::scan(
                reinterpret_cast<std::uintptr_t>(mi.lpBaseOfDll),
                reinterpret_cast<std::uintptr_t>(mi.lpBaseOfDll) + mi.SizeOfImage,
                mzPat);
            ui_result("scan() found version.dll MZ after injection", mzHit != 0);
            if (mzHit)
                std::cout << "       version.dll MZ at " << to_hex(mzHit) << '\n';

            // Also verify via HaxHelper self-dump path.
            char selfPath[MAX_PATH]{};
            GetModuleFileNameA(nullptr, selfPath, MAX_PATH);
            std::string selfExe = selfPath;
            auto sl2 = selfExe.find_last_of("\\/");
            if (sl2 != std::string::npos) selfExe = selfExe.substr(sl2 + 1);

            w32t::HaxHelper hax(selfExe);
            if (hax.dumpMemory()) {
                auto modEntry = w32t::Core::getModuleFromPid(selfPid, selfExe);
                if (modEntry) {
                    // The dump now includes the injected dll's region via PE headers.
                    std::uintptr_t mzHax =
                        hax.findExternalIda(*modEntry, "4D 5A");
                    ui_result("HaxHelper::findExternalIda post-inject MZ", mzHax != 0);
                }
            }
        }
        else {
            ui_warn("Injection failed — try running as Administrator");
        }
    }
}

// =============================================================================
//  Entry point
// =============================================================================
int main()
{
    setupConsole();
    w32t::wsa_init();

    const std::string border = repeat("\xe2\x94\x80", 56);
    std::cout << "\xe2\x94\x8c" << border << "\xe2\x94\x90\n"
        << "\xe2\x94\x82    win32tools v2.0  -  Integration Demo             \xe2\x94\x82\n"
        << "\xe2\x94\x82    TCP/UDP IOCP  |  Scanner v2  |  HaxHelper        \xe2\x94\x82\n"
        << "\xe2\x94\x94" << border << "\xe2\x94\x98\n";

    std::cout << "\nSelect demo:\n"
        << "  1)  Run ALL\n"
        << "  2)  Core\n"
        << "  3)  DriveInfo\n"
        << "  4)  Scanner v2\n"
        << "  5)  HaxHelper (self-dump)\n"
        << "  6)  Packet (all types)\n"
        << "  7)  NamedPipe\n"
        << "  8)  NetworkSocket (sync TCP)\n"
        << "  9)  IocpTcpServer + IocpTcpClient\n"
        << " 10)  IocpUdpServer + IocpUdpClient\n"
        << " 11)  Inject (self-inject + scan)\n"
        << "\n> ";

    int choice = 0;
    std::cin >> choice;

    switch (choice) {
    case 1:
        demo_Core();
        demo_DriveInfo();
        demo_Scanner();
        demo_HaxHelper();
        demo_Packet();
        demo_NamedPipe();
        demo_NetworkSocket();
        demo_IocpTcp();
        demo_IocpUdp();
        demo_Inject();
        break;
    case  2: demo_Core();            break;
    case  3: demo_DriveInfo();       break;
    case  4: demo_Scanner();         break;
    case  5: demo_HaxHelper();       break;
    case  6: demo_Packet();          break;
    case  7: demo_NamedPipe();       break;
    case  8: demo_NetworkSocket();   break;
    case  9: demo_IocpTcp();         break;
    case 10: demo_IocpUdp();         break;
    case 11: demo_Inject();          break;
    default: std::cout << "Unknown option.\n"; break;
    }

    std::cout << "\n[Done] Press Enter to exit...\n";
    std::cin.ignore((std::numeric_limits<std::streamsize>::max)(), '\n');
    std::cin.get();

    w32t::wsa_cleanup();
    return 0;
}