#include <win32tools/Network/IocpTcpServer.hpp>

#include <cstring>

#include <ws2tcpip.h>

namespace w32t {

// ── IoContext ─────────────────────────────────────────────────────────────────

IoContext::IoContext()
    : OVERLAPPED{}
    , socketHandle(INVALID_SOCKET)
    , ioState(State::IoAccept)
    , wsaBuf{}
    , buffer{}
    , bytesToSend(0)
    , bytesSent(0)
{
    // Zero the OVERLAPPED base.
    Internal     = 0;
    InternalHigh = 0;
    Offset       = 0;
    OffsetHigh   = 0;
    hEvent       = nullptr;
}

IoContext::~IoContext() = default;

// ── IocpTcpServer ─────────────────────────────────────────────────────────────

IocpTcpServer::IocpTcpServer()
    : NetworkSocket(Type::Tcp)
    , m_clientContext(nullptr)
    , m_initialised(false)
    , m_iocpHandle(INVALID_HANDLE_VALUE)
{}

IocpTcpServer::~IocpTcpServer()
{
    delete m_clientContext;
    m_clientContext = nullptr;

    if (m_iocpHandle != INVALID_HANDLE_VALUE &&
        m_iocpHandle != nullptr)
    {
        CloseHandle(m_iocpHandle);
        m_iocpHandle = INVALID_HANDLE_VALUE;
    }
}

// ── Public API ────────────────────────────────────────────────────────────────

bool IocpTcpServer::listen(unsigned int port, LPTHREAD_START_ROUTINE workerThread)
{
    // Already listening on this port – nothing to do.
    if (localPort() == static_cast<unsigned short>(port))
        return true;

    trimError(m_errorLog.size());

    if (!initialise(workerThread)) {
        m_errorLog += "IOCP initialisation failed.\n";
        close();
        return false;
    }

    sockaddr_in addr{};
    addr.sin_family      = AF_INET;
    addr.sin_port        = htons(static_cast<u_short>(port));
    addr.sin_addr.s_addr = htonl(INADDR_ANY);

    if (::bind(handle(), reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
        m_errorLog += "bind() failed.\n";
        close();
        return false;
    }

    if (::listen(handle(), SOMAXCONN) != 0) {
        m_errorLog += "listen() failed.\n";
        close();
        return false;
    }

    // Disable send buffering so data is passed straight to the NIC.
    int zero = 0;
    setsockopt(handle(), SOL_SOCKET, SO_SNDBUF,
               reinterpret_cast<const char*>(&zero), sizeof(zero));

    m_initialised = true;
    return true;
}

bool IocpTcpServer::accept(NetworkSocket& /*placeholder*/)
{
    sockaddr_in clientAddr{};
    int addrLen = sizeof(clientAddr);

    m_peerSocket = WSAAccept(handle(),
                              reinterpret_cast<sockaddr*>(&clientAddr),
                              &addrLen,
                              nullptr, 0);

    if (m_peerSocket == INVALID_SOCKET) {
        m_errorLog += "WSAAccept failed.\n";
        return false;
    }

    char peerAddress[INET_ADDRSTRLEN]; // Buffer to hold the string
    InetNtop(AF_INET, &clientAddr.sin_addr, peerAddress, INET_ADDRSTRLEN);

    m_peerAddress = peerAddress;
    m_peerPort    = ntohs(clientAddr.sin_port);

    // Recycle the old context if present.
    delete m_clientContext;
    m_clientContext = associateWithIocp(m_peerSocket, IoContext::State::IoRecv);

    if (!m_clientContext) {
        m_errorLog += "Failed to associate socket with IOCP.\n";
        return false;
    }

    DWORD flags     = 0;
    DWORD recvBytes = 0;

    const int result = WSARecv(m_peerSocket,
                                &m_clientContext->wsaBuf, 1,
                                &recvBytes, &flags,
                                m_clientContext, nullptr);

    if (result == SOCKET_ERROR && WSAGetLastError() != WSA_IO_PENDING) {
        m_errorLog += "WSARecv failed after accept.\n";
        return false;
    }

    return true;
}

// ── Private helpers ───────────────────────────────────────────────────────────

bool IocpTcpServer::initialise(LPTHREAD_START_ROUTINE workerThread)
{
    if (!Socket::create())
        return false;

    SYSTEM_INFO sysInfo{};
    GetSystemInfo(&sysInfo);

    // Create the completion port without associating any handle yet.
    m_iocpHandle = CreateIoCompletionPort(INVALID_HANDLE_VALUE,
                                           nullptr, 0,
                                           sysInfo.dwNumberOfProcessors);
    if (!m_iocpHandle) {
        m_errorLog += "CreateIoCompletionPort failed.\n";
        WSACleanup();
        return false;
    }

    // Spawn 2× processors worker threads (common IOCP best practice).
    const DWORD threadCount = sysInfo.dwNumberOfProcessors * 2;
    for (DWORD i = 0; i < threadCount; ++i) {
        HANDLE hThread = CreateThread(nullptr, 0,
                                       workerThread,
                                       m_iocpHandle,
                                       0, nullptr);
        if (!hThread || hThread == INVALID_HANDLE_VALUE) {
            m_errorLog += "Failed to create worker thread.\n";
            // Don't close an invalid handle.
            if (hThread && hThread != INVALID_HANDLE_VALUE)
                CloseHandle(hThread);
            return false;
        }
        CloseHandle(hThread); // IOCP keeps threads alive via their message pump.
    }

    return true;
}

IoContext* IocpTcpServer::associateWithIocp(SOCKET           socketHandle,
                                             IoContext::State state)
{
    auto* ctx = new IoContext;

    ctx->socketHandle = socketHandle;
    ctx->ioState      = state;
    ctx->bytesToSend  = 0;
    ctx->bytesSent    = 0;
    ctx->wsaBuf.buf   = ctx->buffer;
    ctx->wsaBuf.len   = static_cast<ULONG>(IoContext::k_bufferSize);

    std::memset(ctx->buffer, 0, IoContext::k_bufferSize);

    // Associate the socket with the existing completion port.
    // The completion key is the context pointer itself.
    m_iocpHandle = CreateIoCompletionPort(
        reinterpret_cast<HANDLE>(socketHandle),
        m_iocpHandle,
        reinterpret_cast<ULONG_PTR>(ctx),
        0);

    if (!m_iocpHandle) {
        delete ctx;
        return nullptr;
    }

    return ctx;
}

} // namespace w32t
