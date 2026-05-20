# win32tools

A header-driven C++17 toolkit for Windows system programming. Provides process and memory utilities, high-performance pattern scanning, DLL injection, hardware fingerprinting, IOCP-based async networking (TCP + UDP), synchronous named pipes, and a binary serialisation layer — all under the `w32t` namespace with consistent, RAII-safe APIs.

released by: some person at his private residence
---

## Table of Contents

- [Requirements](#requirements)
- [Project Layout](#project-layout)
- [Module Reference](#module-reference)
  - [Core](#core)
  - [Scanner v2](#scanner-v2)
  - [HaxHelper](#haxhelper)
  - [Inject](#inject)
  - [DriveInfo](#driveinfo)
  - [Packet](#packet)
  - [Socket](#socket)
  - [NetworkSocket](#networksocket)
  - [NamedPipe](#namedpipe)
  - [IocpBase](#iocpbase)
  - [IocpTcpServer / IocpTcpClient](#iocptcpserver--iocptcpclient)
  - [IocpUdpServer / IocpUdpClient](#iocpudpserver--iocpudpclient)
- [Known Issues & Fixes](#known-issues--fixes)
- [Demo (`demo/main.cpp`)](#demo-demomainscpp)
- [Building](#building)
- [License](#license)

---

## Requirements

| Requirement | Details |
|---|---|
| Compiler | MSVC 2019+ (v142 toolset or later) |
| Language standard | C++17 (`/std:c++17`) |
| Platform | Windows 10 / Windows Server 2016 or later (x64) |
| Privileges | Some modules require administrator rights (see per-module notes) |
| Link libraries | `Ws2_32.lib`, `psapi.lib`, `kernel32.lib` |

---

## Project Layout

```
win32tools/
├── Tools/
│   ├── Core.hpp / Core.cpp           # Base process & memory utilities
│   ├── Scanner.hpp / Scanner.cpp     # Pattern scanner v2 (BMH + bitmask)
│   ├── HaxHelper.hpp / HaxHelper.cpp # Remote dump + pattern scan facade
│   ├── Inject.hpp / Inject.cpp       # DLL injection (LoadLibraryW + shellcode)
│   └── DriveInfo.hpp / DriveInfo.cpp # Hardware fingerprinting (HDD, MAC, HWID)
│
├── Network/
│   ├── Packet.hpp / Packet.cpp       # Binary serialisation (LE, length-prefixed)
│   ├── Socket.hpp / Socket.cpp       # RAII Winsock handle wrapper
│   ├── NetworkSocket.hpp / .cpp      # Synchronous TCP/UDP with Packet framing
│   ├── NamedPipe.hpp / NamedPipe.cpp # Synchronous named pipe (server + client)
│   ├── IocpBase.hpp                  # Shared IOCP structs, pool, protocol framing
│   ├── IocpTcpServer.hpp / .cpp      # Async IOCP TCP server (multi-client)
│   ├── IocpTcpClient.hpp / .cpp      # Async IOCP TCP client
│   ├── IocpUdpServer.hpp / .cpp      # Async IOCP UDP server (peer tracking)
│   └── IocpUdpClient.hpp / .cpp      # Async IOCP UDP client (connected + unconnected)
│
└── demo/
    └── main.cpp                      # Stand-alone integration test & demo runner
```

---

## Module Reference

### Core

**Header:** `win32tools/Tools/Core.hpp`

Base class inherited by `HaxHelper` and usable standalone for process introspection and remote memory operations.

#### Process Discovery

```cpp
// Find a single PID by executable name
DWORD pid = w32t::Core::processIdFromExe("notepad.exe");

// Find all PIDs matching an executable name (e.g. svchost.exe)
std::vector<DWORD> pids = w32t::Core::processIdListFromExe("svchost.exe");

// Find a PID by window title and optional class name
DWORD pid = w32t::Core::processIdFromWindow("Untitled - Notepad", "Notepad");
```

#### Module Enumeration

```cpp
// Module info for a DLL loaded in the current process
auto info = w32t::Core::getInternalModuleInfo("ntdll.dll");
// info->lpBaseOfDll, info->SizeOfImage

// Module entry for a DLL in an external process
auto entry = w32t::Core::getModuleFromPid(pid, "game.exe");
// entry->modBaseAddr, entry->modBaseSize
```

Internally retries `CreateToolhelp32Snapshot` up to three times to handle the `ERROR_BAD_LENGTH` race condition present on 64-bit targets.

#### Remote Memory

```cpp
w32t::Core core;

// Allocate RWX memory in a remote process
uintptr_t addr = core.allocRemote(hProcess, size);

// Write a code cave (allocates if needed, advances internal cursor)
uintptr_t base = core.writeCodeCaveRemote(hProcess, shellcode, sizeof(shellcode));

// Write arbitrary bytes, temporarily changing page protection
w32t::Core::writeMemoryRemote(hProcess, destPtr, sourcePtr, size);
```

#### Byte Helpers

```cpp
// Decompose a DWORD into little-endian bytes
auto bytes = w32t::Core::toBytes(0xDEADBEEF);   // {EF, BE, AD, DE}

// Append strings, DWORDs, or byte vectors into a buffer
std::vector<uint8_t> buf;
w32t::Core::appendBytes(buf, 0xCAFEBABEu);
w32t::Core::appendBytes(buf, "win32tools", 10);
w32t::Core::appendBytes(buf, anotherByteVec);
```

---

### Scanner v2

**Header:** `win32tools/Tools/Scanner.hpp`

High-performance byte-pattern scanner using a Boyer–Moore–Horspool (BMH) bad-character skip table, a 64-bit concrete-byte bitmask, and sentinel pre-checks. Up to 6× faster than a naïve `memchr` loop on typical 12–20 byte signatures. Maximum pattern length is 64 bytes.

#### Pattern Creation

Two input formats are supported.

**IDA-style** (`"48 8B ? ? 05 ?? AB"` — spaces delimit bytes, `?` or `??` is wildcard):

```cpp
// Owning (heap-allocated storage — recommended for most uses)
w32t::PatternOwned owned = w32t::PatternOwned::from_ida("48 8B 05 ?? ??");
if (owned.valid()) { /* use owned.get() */ }

// Non-owning (caller provides storage buffer)
uint8_t storage[w32t::kMaxLen];
w32t::Pattern pat{};
w32t::Pattern::from_ida("48 8B 05 ?? ??", storage, pat);
```

**Char-mask** (byte array + `"xxx??x"` mask string):

```cpp
const uint8_t bytes[] = { 0xDE, 0xAD, 0xBE, 0xEF };
w32t::Pattern pat{};
w32t::Pattern::from_char_mask(bytes, "xxxx", pat);

// Or via PatternOwned
auto owned = w32t::PatternOwned::from_char_mask(bytes, "xxxx");
```

#### Scanning Functions

```cpp
// Scan a flat memory region — returns pointer to first match or nullptr
const uint8_t* hit = w32t::scan_region(base, size, pat, align /*default 1*/);

// Scan a VA range respecting VirtualQuery page permissions — returns address or 0
uintptr_t addr = w32t::scan(start, end, pat, align);

// Find ALL matches — returns count of hits written to out_buf
uintptr_t results[16]{};
size_t count = w32t::scan_all(start, end, pat, results, 16);

// Scan for MULTIPLE patterns in a single pass — returns number of patterns found
w32t::Pattern pats[2] = { patA, patB };
uintptr_t addrs[2]    = {};
size_t found = w32t::scan_multi(start, end, pats, addrs, 2);
```

#### Legacy Shim

```cpp
// Drop-in replacement for old-style (bytes, mask) scanner calls
uintptr_t addr = w32t::findPattern(regionBase, regionSize, patternBytes, "xxx??x");
```

#### Page-Permission Helper

```cpp
MEMORY_BASIC_INFORMATION mbi{};
VirtualQuery(addr, &mbi, sizeof(mbi));
if (w32t::is_readable(mbi)) { /* safe to read */ }
```

---

### HaxHelper

**Header:** `win32tools/Tools/HaxHelper.hpp`  
**Inherits:** `Core`

Dumps a remote (or self) process module into a local buffer and runs Scanner v2 over the copy, returning addresses translated back into the target process's virtual address space.

```cpp
w32t::HaxHelper hax("target.exe");

// Dump the target module (idempotent — cached after first successful call)
if (hax.dumpMemory()) {
    std::cout << hax.dumpedSize() << " bytes dumped\n";
}

// Get the MODULEENTRY32 for address translation
auto mod = w32t::Core::getModuleFromPid(pid, "target.exe");

// IDA-style scan — returns address in the REMOTE process
uintptr_t addr = hax.findExternalIda(*mod, "48 8B 05 ?? ?? ?? ??");

// Char-mask scan
const uint8_t pat[] = { 0x48, 0x8B, 0x05 };
uintptr_t addr = hax.findExternalBytes(*mod, pat, "xxx");

// Invalidate cached dump to force a fresh read on next call
hax.invalidateDump();
```

`HaxHelper` automatically attempts to enable `SeDebugPrivilege` before opening the target process. Opening with only `PROCESS_VM_READ | PROCESS_QUERY_INFORMATION` keeps it compatible with cross-session targets even under standard administrator rights.

**Static helper** (delegates to `Inject` internally):

```cpp
w32t::HaxHelper::injectDll(targetPid, "C:\\path\\payload.dll");
```

---

### Inject

**Header:** `win32tools/Tools/Inject.hpp`

DLL injection via two techniques.

#### Technique 1 — `LoadLibraryW` + `CreateRemoteThread` (recommended)

Standard and reliable. Uses UTF-16 path to support Unicode DLL paths correctly.

```cpp
w32t::Inject injector("C:\\payload.dll");
bool ok = injector.injectIntoProcess(targetPid);

// Or set path separately
injector.setDllPath("C:\\other.dll");
injector.injectIntoProcess(targetPid);

// Convenience one-shot overload
injector.injectIntoProcess(targetPid, "C:\\payload.dll");
```

Steps performed internally: resolve `LoadLibraryW` address ? `OpenProcess` ? `VirtualAllocEx` + `WriteProcessMemory` the UTF-16 path ? `CreateRemoteThread` ? `WaitForSingleObject` ? verify exit code ? clean up.

#### Technique 2 — x64 Shellcode

Builds and executes a minimal x64 shellcode stub that calls `LoadLibraryA` directly, respecting the x64 calling convention (RCX + 40-byte shadow space).

```cpp
bool ok = injector.injectWithShellcode(targetPid);
```

> **Note:** Both techniques require administrator privileges and are blocked for PID 0 (idle) and PID 4 (System). `injectIntoProcess` validates that the DLL file exists on disk before proceeding.

---

### DriveInfo

**Header:** `win32tools/Tools/DriveInfo.hpp`

Reads hardware identifiers. Results are cached after the first successful call.

```cpp
w32t::DriveInfo di;

// HDD serial number (SMART_RCV_DRIVE_DATA IOCTL — requires admin, IDE/SATA only)
std::string serial = di.hddSerial();

// Network adapter MAC address (no elevated privileges required)
std::string mac = di.macAddress();

// Motherboard serial (WMI-based)
std::string mobo = di.getMoboSerial();

// All collected drive serials
std::vector<std::string>& serials = di.getSerials();

// Build a composite HWID (interleaves characters of two strings)
std::string hwid = w32t::DriveInfo::buildHwid(serials[0] + mobo, mac);

// Full auto-generated HWID
std::string master = di.generateMasterHWID();

// Diagnostic log (empty on success)
std::cout << di.diag();
```

> **Note:** NVMe drives do not expose the SMART interface used here. NVMe pass-through requires a separate vendor-specific IOCTL and will return an empty serial. The SMART path requires `GENERIC_READ | GENERIC_WRITE` access to `\\.\PhysicalDriveN`, which requires administrator privileges.

---

### Packet

**Header:** `win32tools/Network/Packet.hpp`

Zero-dependency binary serialisation buffer. Wire layout is little-endian. Strings are length-prefixed with a `uint16_t`. Compatible with `NetworkSocket::send` / `recv`.

```cpp
w32t::Packet pkt;

// Write
pkt << static_cast<uint8_t>(0xAB);
pkt << static_cast<uint32_t>(0xDEADBEEF);
pkt << true;
pkt << 3.14f;
pkt << std::string("hello");
pkt << "c_string";             // null-terminated, stored as uint16 len + bytes

// Raw write (no length prefix)
pkt.writeRaw(ptr, len);

// Read (reset cursor first)
pkt.pos = 0;
uint8_t u8{};     pkt >> u8;
uint32_t u32{};   pkt >> u32;
bool b{};         pkt >> b;
float f{};        pkt >> f;
std::string s;    pkt >> s;
char buf[64]{};   pkt >> buf;

// Introspection
pkt.size();           // total bytes written
pkt.canRead(n);       // true if n bytes remain from current cursor
pkt.clear();          // reset buffer and cursor
```

Supported types: `uint8/16/32/64`, `int8/16/32/64`, `float`, `double`, `bool`, `const char*`, `std::string`.

---

### Socket

**Header:** `win32tools/Network/Socket.hpp`

RAII wrapper around a Winsock `SOCKET` handle. Non-copyable, movable. Base class for `NetworkSocket`.

```cpp
// Initialise WSA once per process
w32t::wsa_init();

w32t::Socket sock(w32t::Socket::Type::Tcp);
sock.create();

sock.localAddress();   // "127.0.0.1"
sock.localPort();      // uint16_t
sock.peerAddress();
sock.isConnected();
sock.lastError();      // human-readable WSA error string
sock.close();

w32t::wsa_cleanup();
```

---

### NetworkSocket

**Header:** `win32tools/Network/NetworkSocket.hpp`  
**Inherits:** `Socket`

Synchronous TCP client / UDP socket with `Packet` framing. TCP send prepends a 4-byte LE length header; TCP recv reads the header then the full payload.

```cpp
w32t::NetworkSocket client(w32t::Socket::Type::Tcp);
client.create();
client.connectTo("127.0.0.1", 9000);

// Send a Packet (4-byte length prefix prepended automatically)
w32t::Packet pkt;
pkt << std::string("hello") << uint32_t(42);
client.send(pkt);

// Receive a Packet
w32t::Packet reply;
client.recv(reply);

// Raw I/O (no framing)
client.sendRaw(data, len);
client.recvRaw(buf, len);

// UDP peer for connected-mode UDP
client.setUdpPeer("10.0.0.1", 9001);
```

---

### NamedPipe

**Header:** `win32tools/Network/NamedPipe.hpp`

Synchronous Windows named pipe. Server side calls `CreateNamedPipe` + `ConnectNamedPipe`; client side calls `WaitNamedPipe` + `CreateFile`. Buffer size is 4096 bytes.

```cpp
// Server thread
w32t::NamedPipe server("MyPipeName");
server.serverConnect();            // blocks until client connects
char buf[256]{};
server.read(buf, sizeof(buf));
server.write("pong", 5);

// Client thread
w32t::NamedPipe client("MyPipeName");
client.clientOpen();
client.write("ping", 5);
client.read(buf, sizeof(buf));

client.disconnect();
client.close();
```

The full UNC path `\\.\pipe\MyPipeName` is constructed internally.

---

### IocpBase

**Header:** `win32tools/Network/IocpBase.hpp`

Internal infrastructure shared by all four IOCP classes. Not used directly.

Provides: `IocpOp` (OVERLAPPED wrapper), `IoContext`, `SendReq` (16-byte-aligned SLIST pool node), `NetProtocol` enum, `detectProtocol()`, and lock-free pool helpers (`pool_init`, `pool_acquire`, `pool_release`, `pool_drain`).

**Protocol auto-detection:** the first byte received determines framing mode. A printable ASCII byte (0x20–0x7E) selects `Telnet` (newline-delimited text); any other byte selects `Packet` (4-byte LE length prefix).

**Constants:**

| Constant | Value | Purpose |
|---|---|---|
| `kRecvBufSize` | 4096 | Per-operation receive buffer |
| `kStagingSize` | 8192 | Reassembly staging buffer |
| `kMaxPayload` | 4092 | Maximum single message payload |
| `kPoolInitial` | 128 | Pre-allocated send-request nodes |
| `kIdleTimeoutMs` | 300 000 ms | Default idle disconnect threshold |

---

### IocpTcpServer / IocpTcpClient

**Headers:** `win32tools/Network/IocpTcpServer.hpp`, `win32tools/Network/IocpTcpClient.hpp`

Fully asynchronous TCP server and client built on Windows IOCP. All I/O dispatches through a configurable worker thread pool. Callbacks fire on worker threads — keep them short and non-blocking.

#### Server

```cpp
w32t::TcpServerCallbacks cb;
cb.on_connect = [](w32t::TcpClientHandle c) {
    printf("client %d connected from %s:%d\n", c->id, c->ip, c->port);
};
cb.on_data = [&](w32t::TcpClientHandle c, const char* data, int len) {
    // data is already de-framed (length prefix stripped)
    server.send(c, data, len);   // echo
};
cb.on_close = [](w32t::TcpClientHandle c) { /* cleanup */ };

w32t::IocpTcpServer server;
server.init(cb, /*workerCount=*/2);

// Blocking accept loop — run on a dedicated thread
std::thread t([&]{ server.listen(9000); });

// Send to a specific client
server.send(clientHandle, data, len);

// Broadcast to all connected clients
server.broadcast(data, len);
server.broadcastExcept(excludeHandle, data, len);

// Client registry
int count = server.clientCount();
TcpClientHandle h = server.findById(id);
server.iterateClients([](TcpClientHandle c) { /* visit */ });
// WARNING: do not call server.close() from inside the iterator callback

server.close(clientHandle);
server.stop();     // unblocks listen()
server.shutdown(); // drains workers, releases all resources
```

#### Client

```cpp
w32t::TcpClientCallbacks cb;
cb.on_connect = []() { puts("connected"); };
cb.on_data    = [](const char* data, int len) { /* handle message */ };
cb.on_close   = []() { puts("disconnected"); };

w32t::IocpTcpClient client;
client.connect("127.0.0.1", 9000, cb);

// Packet mode: 4-byte LE length prepended automatically
// Telnet mode: bare '\n' normalised to '\r\n'
client.send(data, len);

client.connected();    // thread-safe state query
client.remoteIp();
client.remotePort();
client.disconnect();
```

Both server and client are thread-safe for `send()` and `disconnect()` from any thread. A timer thread on the server reaps idle connections after `kIdleTimeoutMs` milliseconds.

---

### IocpUdpServer / IocpUdpClient

**Headers:** `win32tools/Network/IocpUdpServer.hpp`, `win32tools/Network/IocpUdpClient.hpp`

Asynchronous UDP over IOCP with automatic peer tracking on the server side. Multiple concurrent receive operations are posted simultaneously (configurable, default 4 for server, 2 for client) to saturate throughput on multi-core hardware.

#### Server

```cpp
w32t::UdpServerCallbacks cb;
cb.on_new_peer    = [](w32t::UdpPeer* p) { printf("new peer %s:%d\n", p->ip, p->port); };
cb.on_data        = [&](w32t::UdpPeer* p, const char* data, int len) {
    udpSrv.sendTo(p, data, len);   // echo
};
cb.on_peer_timeout = [](w32t::UdpPeer* p) { /* peer idle-expired */ };

w32t::IocpUdpServer udpSrv(/*concurrentRecvs=*/4);
udpSrv.init(cb, /*workerCount=*/2);
udpSrv.listen(9001);

// Send to a specific peer by handle or address
udpSrv.sendTo(peerHandle, data, len);
udpSrv.sendTo(sockaddrStorage, data, len);

// Broadcast to all known peers
udpSrv.broadcast(data, len);

// Peer lookup
UdpPeer* p = udpSrv.findPeer("192.168.1.10", 54321);
UdpPeer* p = udpSrv.findPeerById(id);
udpSrv.iteratePeers([](UdpPeer* p) { /* visit */ });

udpSrv.setIdleTimeout(60000);  // ms; 0 = disabled
udpSrv.peerCount();
udpSrv.boundPort();
udpSrv.stop();
udpSrv.shutdown();
```

#### Client — Connected Mode

```cpp
w32t::UdpClientCallbacks cb;
cb.on_data  = [](const sockaddr_storage& from, const char* data, int len) { /* ... */ };
cb.on_close = []() {};

w32t::IocpUdpClient client;
client.connectTo("127.0.0.1", 9001, cb, /*localPort=*/0);
client.send(data, len);
client.disconnect();
```

#### Client — Unconnected (Bind) Mode

```cpp
w32t::IocpUdpClient client2;
client2.bind(/*localPort=*/0, cb);   // OS assigns ephemeral port

sockaddr_storage dest{};
// fill dest manually (sockaddr_in cast etc.)
client2.sendTo(dest, data, len);
client2.disconnect();
```

---

## Known Issues & Fixes

### 1. `IocpTcpServer::listen()` is blocking

`listen()` runs the accept loop on the calling thread indefinitely. Always call it from a dedicated `std::thread` and pair it with `stop()` + `thread::join()` on teardown, as shown in the demo.

---

## Demo (`demo/main.cpp`)

The `demo/` folder contains a standalone integration test runner (`main.cpp`) that exercises every module. It is compiled separately from the library itself — it is included for reference and manual testing only.

> Build the library first, then build the demo against it. Do not add `main.cpp` to your library project.

### What the demo covers

The demo presents an interactive menu and can run all tests sequentially or individually:

| # | Test | What it exercises |
|---|---|---|
| 1 | **Core** | `processIdFromExe`, `processIdListFromExe`, `processIdFromWindow`, `getInternalModuleInfo`, `getModuleFromPid`, `toBytes`, `appendBytes` |
| 2 | **DriveInfo** | Opens `\\.\PhysicalDriveN`, reads HDD serial via SMART IOCTL, retrieves MAC address, builds composite HWID |
| 3 | **Scanner v2** | IDA pattern, char-mask pattern, `scan_all` (all occurrences), `scan_multi` (two patterns in one pass), wildcard-first slow path, alignment constraints, edge cases (null base, undersized region, empty pattern), live self-scan via `VirtualQuery` |
| 4 | **HaxHelper** | Self-process dump, `findExternalBytes` (char-mask), `findExternalIda`, both overloads agreeing on the same address, `invalidateDump` + re-dump |
| 5 | **Packet** | Full round-trip for all supported types: `uint8/16/32/64`, `bool`, `float`, `double`, `std::string`, `const char*` |
| 6 | **NamedPipe** | Intra-process bidirectional pipe: server thread posts a `PONG`, client thread sends `PING` and reads back |
| 7 | **NetworkSocket** | Synchronous TCP loopback on port 19010 with `Packet` framing; server decodes a struct, replies with ACK |
| 8 | **IocpTcpServer + IocpTcpClient** | Async TCP on port 19011; welcome message, echo, second client, broadcast, `clientCount`, `findById`, `iterateClients` |
| 9 | **IocpUdpServer + IocpUdpClient** | Async UDP on port 19020; connected client, unconnected client, echo, broadcast, `peerCount`, `findPeerById` |
| 10 | **Inject** | Self-injects `version.dll` into the current process via `LoadLibraryW` + `CreateRemoteThread`, then verifies the load by scanning for the MZ header with both `scan()` and `HaxHelper::findExternalIda` |

### Admin-sensitive tests

Tests 2 (DriveInfo HDD serial) and 10 (Inject) require the demo to be run as Administrator. All other tests run under a standard user account. The demo degrades gracefully — failing tests print a warning rather than aborting.

### Building the demo

```bat
:: From the repository root
cl /std:c++17 /W3 /EHsc /I. ^
   demo\main.cpp ^
   Tools\Core.cpp Tools\Scanner.cpp Tools\HaxHelper.cpp ^
   Tools\Inject.cpp Tools\DriveInfo.cpp ^
   Network\Socket.cpp Network\NetworkSocket.cpp ^
   Network\NamedPipe.cpp Network\Packet.cpp ^
   Network\IocpTcpServer.cpp Network\IocpTcpClient.cpp ^
   Network\IocpUdpServer.cpp Network\IocpUdpClient.cpp ^
   /link Ws2_32.lib psapi.lib /out:demo\win32tools_demo.exe
```

---

## Building

### MSVC (recommended)

Add all `.cpp` files in `Tools/` and `Network/` to your project. Set `/std:c++17` and add the repository root to your include search paths so that `<win32tools/...>` resolves correctly.

Link: `Ws2_32.lib`, `psapi.lib`.

`Socket.hpp` emits `#pragma comment(lib, "Ws2_32.lib")` automatically on MSVC.

### CMake skeleton

```cmake
cmake_minimum_required(VERSION 3.20)
project(win32tools CXX)

set(CMAKE_CXX_STANDARD 17)

file(GLOB_RECURSE W32T_SOURCES Tools/*.cpp Network/*.cpp)

add_library(win32tools STATIC ${W32T_SOURCES})
target_include_directories(win32tools PUBLIC ${CMAKE_SOURCE_DIR})
target_link_libraries(win32tools PUBLIC Ws2_32 psapi)

# Optional: demo executable
add_executable(win32tools_demo demo/main.cpp)
target_link_libraries(win32tools_demo PRIVATE win32tools)
```

---

## License

This project is provided as-is for educational and research purposes. Use responsibly and only on systems you own or have explicit authorisation to access.
