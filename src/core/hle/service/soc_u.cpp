// Copyright 2014 Citra Emulator Project
// Licensed under GPLv2 or any later version
// Refer to the license.txt file included.

#include <algorithm>
#include <cstring>
#include <type_traits>
#include <vector>
#include "common/archives.h"
#include "common/assert.h"
#include "common/bit_field.h"
#include "common/common_types.h"
#include "common/logging/log.h"
#include "common/scope_exit.h"
#include "common/swap.h"
#include "core/core.h"
#include "core/hle/ipc_helpers.h"
#include "core/hle/kernel/shared_memory.h"
#include "core/hle/result.h"
#include "core/hle/service/soc_u.h"

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>

// MinGW does not define several errno constants
#ifndef _MSC_VER
#define EBADMSG 104
#define ENODATA 120
#define ENOMSG 122
#define ENOSR 124
#define ENOSTR 125
#define ETIME 137
#endif // _MSC_VER
#else
#include <cerrno>
#include <arpa/inet.h>
#include <fcntl.h>
#include <ifaddrs.h>
#include <netdb.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#endif

#ifdef _WIN32
#define WSAEAGAIN WSAEWOULDBLOCK
#define WSAEMULTIHOP -1 // Invalid dummy value
#define ERRNO(x) WSA##x
#define GET_ERRNO WSAGetLastError()
#define poll(x, y, z) WSAPoll(x, y, z);
#else
#define ERRNO(x) x
#define GET_ERRNO errno
#define closesocket(x) close(x)
#endif

SERIALIZE_EXPORT_IMPL(Service::SOC::SOC_U)

namespace Service::SOC {

const s32 SOCKET_ERROR_VALUE = -1;

/// Holds the translation from system network errors to 3DS network errors
static const std::unordered_map<int, int> error_map = {{
    {E2BIG, 1},
    {ERRNO(EACCES), 2},
    {ERRNO(EADDRINUSE), 3},
    {ERRNO(EADDRNOTAVAIL), 4},
    {ERRNO(EAFNOSUPPORT), 5},
    {ERRNO(EAGAIN), 6},
    {ERRNO(EALREADY), 7},
    {ERRNO(EBADF), 8},
    {EBADMSG, 9},
    {EBUSY, 10},
    {ECANCELED, 11},
    {ECHILD, 12},
    {ERRNO(ECONNABORTED), 13},
    {ERRNO(ECONNREFUSED), 14},
    {ERRNO(ECONNRESET), 15},
    {EDEADLK, 16},
    {ERRNO(EDESTADDRREQ), 17},
    {EDOM, 18},
    {ERRNO(EDQUOT), 19},
    {EEXIST, 20},
    {ERRNO(EFAULT), 21},
    {EFBIG, 22},
    {ERRNO(EHOSTUNREACH), 23},
    {EIDRM, 24},
    {EILSEQ, 25},
    {ERRNO(EINPROGRESS), 26},
    {ERRNO(EINTR), 27},
    {ERRNO(EINVAL), 28},
    {EIO, 29},
    {ERRNO(EISCONN), 30},
    {EISDIR, 31},
    {ERRNO(ELOOP), 32},
    {ERRNO(EMFILE), 33},
    {EMLINK, 34},
    {ERRNO(EMSGSIZE), 35},
#ifdef EMULTIHOP
    {ERRNO(EMULTIHOP), 36},
#endif
    {ERRNO(ENAMETOOLONG), 37},
    {ERRNO(ENETDOWN), 38},
    {ERRNO(ENETRESET), 39},
    {ERRNO(ENETUNREACH), 40},
    {ENFILE, 41},
    {ERRNO(ENOBUFS), 42},
#ifdef ENODATA
    {ENODATA, 43},
#endif
    {ENODEV, 44},
    {ENOENT, 45},
    {ENOEXEC, 46},
    {ENOLCK, 47},
    {ENOLINK, 48},
    {ENOMEM, 49},
    {ENOMSG, 50},
    {ERRNO(ENOPROTOOPT), 51},
    {ENOSPC, 52},
#ifdef ENOSR
    {ENOSR, 53},
#endif
#ifdef ENOSTR
    {ENOSTR, 54},
#endif
    {ENOSYS, 55},
    {ERRNO(ENOTCONN), 56},
    {ENOTDIR, 57},
    {ERRNO(ENOTEMPTY), 58},
    {ERRNO(ENOTSOCK), 59},
    {ENOTSUP, 60},
    {ENOTTY, 61},
    {ENXIO, 62},
    {ERRNO(EOPNOTSUPP), 63},
    {EOVERFLOW, 64},
    {EPERM, 65},
    {EPIPE, 66},
    {EPROTO, 67},
    {ERRNO(EPROTONOSUPPORT), 68},
    {ERRNO(EPROTOTYPE), 69},
    {ERANGE, 70},
    {EROFS, 71},
    {ESPIPE, 72},
    {ESRCH, 73},
    {ERRNO(ESTALE), 74},
#ifdef ETIME
    {ETIME, 75},
#endif
    {ERRNO(ETIMEDOUT), 76},
}};

/// Converts a network error from platform-specific to 3ds-specific
static int TranslateError(int error) {
    const auto& found = error_map.find(error);
    if (found != error_map.end()) {
        return -found->second;
    }
    return error;
}

/// Holds the translation from system network socket options to 3DS network socket options
/// Note: -1 = No effect/unavailable
static const std::unordered_map<int, int> sockopt_map = {{
    {0x0004, SO_REUSEADDR},
    {0x0080, SO_LINGER},
    {0x0100, -1},
    {0x1001, SO_SNDBUF},
    {0x1002, SO_RCVBUF},
    {0x1003, -1},
#ifdef _WIN32
    /// Unsupported in WinSock2
    {0x1004, -1},
#else
    {0x1004, SO_RCVLOWAT},
#endif
    {0x1008, SO_TYPE},
    {0x1009, SO_ERROR},
}};

/// Converts a socket option from platform-specific to 3ds-specific
static int TranslateSockOpt(int opt) {
    const auto& found = sockopt_map.find(opt);
    if (found != sockopt_map.end()) {
        return found->second;
    }
    return opt;
}

/// Structure to represent the 3ds' pollfd structure, which is different than most implementations
struct CTRPollFD {
    u32 fd; ///< Socket handle

    union Events {
        u32 hex; ///< The complete value formed by the flags
        BitField<0, 1, u32> pollin;
        BitField<1, 1, u32> pollpri;
        BitField<2, 1, u32> pollhup;
        BitField<3, 1, u32> pollerr;
        BitField<4, 1, u32> pollout;
        BitField<5, 1, u32> pollnval;

        /// Translates the resulting events of a Poll operation from platform-specific to 3ds
        /// specific
        static Events TranslateTo3DS(u32 input_event) {
            Events ev = {};
            if (input_event & POLLIN)
                ev.pollin.Assign(1);
            if (input_event & POLLPRI)
                ev.pollpri.Assign(1);
            if (input_event & POLLHUP)
                ev.pollhup.Assign(1);
            if (input_event & POLLERR)
                ev.pollerr.Assign(1);
            if (input_event & POLLOUT)
                ev.pollout.Assign(1);
            if (input_event & POLLNVAL)
                ev.pollnval.Assign(1);
            return ev;
        }

        /// Translates the resulting events of a Poll operation from 3ds specific to platform
        /// specific
        static u32 TranslateToPlatform(Events input_event, bool isOutput) {
#if _WIN32
            constexpr bool isWin = true;
#else
            constexpr bool isWin = false;
#endif

            u32 ret = 0;
            if (input_event.pollin)
                ret |= POLLIN;
            if (input_event.pollpri && !isWin)
                ret |= POLLPRI;
            if (input_event.pollhup && (!isWin || isOutput))
                ret |= POLLHUP;
            if (input_event.pollerr && (!isWin || isOutput))
                ret |= POLLERR;
            if (input_event.pollout)
                ret |= POLLOUT;
            if (input_event.pollnval && (isWin && isOutput))
                ret |= POLLNVAL;
            return ret;
        }
    };
    Events events;  ///< Events to poll for (input)
    Events revents; ///< Events received (output)

    /// Converts a platform-specific pollfd to a 3ds specific structure
    static CTRPollFD FromPlatform(SOC::SOC_U& socu, pollfd const& fd) {
        CTRPollFD result;
        result.events.hex = Events::TranslateTo3DS(fd.events).hex;
        result.revents.hex = Events::TranslateTo3DS(fd.revents).hex;
        for (auto iter = socu.open_sockets.begin(); iter != socu.open_sockets.end(); ++iter) {
            if (iter->second.socket_fd == fd.fd) {
                result.fd = iter->first;
                break;
            }
        }
        return result;
    }

    /// Converts a 3ds specific pollfd to a platform-specific structure
    static pollfd ToPlatform(SOC::SOC_U& socu, CTRPollFD const& fd) {
        pollfd result;
        result.events = Events::TranslateToPlatform(fd.events, false);
        result.revents = Events::TranslateToPlatform(fd.revents, true);
        auto iter = socu.open_sockets.find(fd.fd);
        result.fd = (iter != socu.open_sockets.end()) ? iter->second.socket_fd : 0;
        return result;
    }
};
static_assert(std::is_trivially_copyable_v<CTRPollFD>,
              "CTRPollFD is used with std::memcpy and must be trivially copyable");

/// Union to represent the 3ds' sockaddr structure
union CTRSockAddr {
    /// Structure to represent a raw sockaddr
    struct {
        u8 len;           ///< The length of the entire structure, only the set fields count
        u8 sa_family;     ///< The address family of the sockaddr
        u8 sa_data[0x1A]; ///< The extra data, this varies, depending on the address family
    } raw;

    /// Structure to represent the 3ds' sockaddr_in structure
    struct CTRSockAddrIn {
        u8 len;        ///< The length of the entire structure
        u8 sin_family; ///< The address family of the sockaddr_in
        u16 sin_port;  ///< The port associated with this sockaddr_in
        u32 sin_addr;  ///< The actual address of the sockaddr_in
    } in;

    /// Convert a 3DS CTRSockAddr to a platform-specific sockaddr
    static sockaddr ToPlatform(CTRSockAddr const& ctr_addr) {
        sockaddr result;
        result.sa_family = ctr_addr.raw.sa_family;
        memset(result.sa_data, 0, sizeof(result.sa_data));

        // We can not guarantee ABI compatibility between platforms so we copy the fields manually
        switch (result.sa_family) {
        case AF_INET: {
            sockaddr_in* result_in = reinterpret_cast<sockaddr_in*>(&result);
            result_in->sin_port = ctr_addr.in.sin_port;
            result_in->sin_addr.s_addr = ctr_addr.in.sin_addr;
            memset(result_in->sin_zero, 0, sizeof(result_in->sin_zero));
            break;
        }
        default:
            ASSERT_MSG(false, "Unhandled address family (sa_family) in CTRSockAddr::ToPlatform");
            break;
        }
        return result;
    }

    /// Convert a platform-specific sockaddr to a 3DS CTRSockAddr
    static CTRSockAddr FromPlatform(sockaddr const& addr) {
        CTRSockAddr result;
        result.raw.sa_family = static_cast<u8>(addr.sa_family);
        // We can not guarantee ABI compatibility between platforms so we copy the fields manually
        switch (result.raw.sa_family) {
        case AF_INET: {
            sockaddr_in const* addr_in = reinterpret_cast<sockaddr_in const*>(&addr);
            result.raw.len = sizeof(CTRSockAddrIn);
            result.in.sin_port = addr_in->sin_port;
            result.in.sin_addr = addr_in->sin_addr.s_addr;
            break;
        }
        default:
            ASSERT_MSG(false, "Unhandled address family (sa_family) in CTRSockAddr::ToPlatform");
            break;
        }
        return result;
    }
};

struct CTRAddrInfo {
    s32_le ai_flags;
    s32_le ai_family;
    s32_le ai_socktype;
    s32_le ai_protocol;
    s32_le ai_addrlen;
    char ai_canonname[256];
    CTRSockAddr ai_addr;

    /// Converts a platform-specific addrinfo to a 3ds addrinfo.
    static CTRAddrInfo FromPlatform(const addrinfo& addr) {
        CTRAddrInfo ctr_addr{};

        ctr_addr.ai_flags = addr.ai_flags;
        ctr_addr.ai_family = addr.ai_family;
        ctr_addr.ai_socktype = addr.ai_socktype;
        ctr_addr.ai_protocol = addr.ai_protocol;
        if (addr.ai_canonname)
            std::strncpy(ctr_addr.ai_canonname, addr.ai_canonname, sizeof(ctr_addr.ai_canonname));

        ctr_addr.ai_addr = CTRSockAddr::FromPlatform(*addr.ai_addr);
        ctr_addr.ai_addrlen = ctr_addr.ai_addr.raw.len;

        return ctr_addr;
    }
};

static_assert(sizeof(CTRAddrInfo) == 0x130, "Size of CTRAddrInfo is not correct");

void SOC_U::PreTimerAdjust() {
    adjust_value_last = std::chrono::steady_clock::now();
}

void SOC_U::PostTimerAdjust(Kernel::HLERequestContext& ctx, const std::string& caller_method) {
    std::chrono::time_point<std::chrono::steady_clock> new_timer = std::chrono::steady_clock::now();
    ASSERT(new_timer >= adjust_value_last);
    ctx.SleepClientThread(
        fmt::format("soc_u::{}", caller_method),
        std::chrono::duration_cast<std::chrono::nanoseconds>(new_timer - adjust_value_last),
        nullptr);
}

void SOC_U::CleanupSockets() {
    for (const auto sock : open_sockets)
        closesocket(sock.second.socket_fd);
    open_sockets.clear();
}

void SOC_U::Socket(Kernel::HLERequestContext& ctx) {
    IPC::RequestParser rp(ctx, 0x02, 3, 2);
    u32 domain = rp.Pop<u32>(); // Address family
    u32 type = rp.Pop<u32>();
    u32 protocol = rp.Pop<u32>();
    rp.PopPID();

    IPC::RequestBuilder rb = rp.MakeBuilder(2, 0);

    // Only 0 is allowed according to 3dbrew, using 0 will let the OS decide which protocol to use
    if (protocol != 0) {
        rb.Push(UnimplementedFunction(ErrorModule::SOC)); // TODO(Subv): Correct error code
        rb.Skip(1, false);
        return;
    }

    if (domain != AF_INET) {
        rb.Push(UnimplementedFunction(ErrorModule::SOC)); // TODO(Subv): Correct error code
        rb.Skip(1, false);
        return;
    }

    if (type != SOCK_DGRAM && type != SOCK_STREAM) {
        rb.Push(UnimplementedFunction(ErrorModule::SOC)); // TODO(Subv): Correct error code
        rb.Skip(1, false);
        return;
    }

    u64 ret = static_cast<u64>(::socket(domain, type, protocol));
    u32 socketHandle = GetNextSocketID();

    if ((s64)ret != SOCKET_ERROR_VALUE)
        open_sockets[socketHandle] = {static_cast<decltype(SocketHolder::socket_fd)>(ret), true};

    if ((s64)ret == SOCKET_ERROR_VALUE)
        ret = TranslateError(GET_ERRNO);

    rb.Push(RESULT_SUCCESS);
    rb.Push(socketHandle);
}

void SOC_U::Bind(Kernel::HLERequestContext& ctx) {
    IPC::RequestParser rp(ctx, 0x05, 2, 4);
    u32 socket_handle = rp.Pop<u32>();
    auto fd_info = open_sockets.find(socket_handle);
    if (fd_info == open_sockets.end()) {
        IPC::RequestBuilder rb = rp.MakeBuilder(1, 0);
        rb.Push(ERR_INVALID_HANDLE);
        return;
    }
    u32 len = rp.Pop<u32>();
    rp.PopPID();
    auto sock_addr_buf = rp.PopStaticBuffer();

    CTRSockAddr ctr_sock_addr;
    std::memcpy(&ctr_sock_addr, sock_addr_buf.data(), sizeof(CTRSockAddr));

    sockaddr sock_addr = CTRSockAddr::ToPlatform(ctr_sock_addr);

    s32 ret = ::bind(fd_info->second.socket_fd, &sock_addr, std::max<u32>(sizeof(sock_addr), len));

    if (ret != 0)
        ret = TranslateError(GET_ERRNO);

    IPC::RequestBuilder rb = rp.MakeBuilder(2, 0);
    rb.Push(RESULT_SUCCESS);
    rb.Push(ret);
}

void SOC_U::Fcntl(Kernel::HLERequestContext& ctx) {
    IPC::RequestParser rp(ctx, 0x13, 3, 2);
    u32 socket_handle = rp.Pop<u32>();
    auto fd_info = open_sockets.find(socket_handle);
    if (fd_info == open_sockets.end()) {
        IPC::RequestBuilder rb = rp.MakeBuilder(1, 0);
        rb.Push(ERR_INVALID_HANDLE);
        return;
    }
    u32 ctr_cmd = rp.Pop<u32>();
    u32 ctr_arg = rp.Pop<u32>();
    rp.PopPID();

    u32 posix_ret = 0; // TODO: Check what hardware returns for F_SETFL (unspecified by POSIX)
    SCOPE_EXIT({
        IPC::RequestBuilder rb = rp.MakeBuilder(2, 0);
        rb.Push(RESULT_SUCCESS);
        rb.Push(posix_ret);
    });

    if (ctr_cmd == 3) { // F_GETFL
#ifdef _WIN32
        posix_ret = 0;
        if (fd_info->second.blocking == false)
            posix_ret |= 4; // O_NONBLOCK
#else
        int ret = ::fcntl(fd_info->second.socket_fd, F_GETFL, 0);
        if (ret == SOCKET_ERROR_VALUE) {
            posix_ret = TranslateError(GET_ERRNO);
            return;
        }
        posix_ret = 0;
        if (ret & O_NONBLOCK)
            posix_ret |= 4; // O_NONBLOCK
#endif
    } else if (ctr_cmd == 4) { // F_SETFL
#ifdef _WIN32
        unsigned long tmp = (ctr_arg & 4 /* O_NONBLOCK */) ? 1 : 0;
        int ret = ioctlsocket(fd_info->second.socket_fd, FIONBIO, &tmp);
        if (ret == SOCKET_ERROR_VALUE) {
            posix_ret = TranslateError(GET_ERRNO);
            return;
        }
        auto iter = open_sockets.find(socket_handle);
        if (iter != open_sockets.end())
            iter->second.blocking = (tmp == 0);
#else
        int flags = ::fcntl(fd_info->second.socket_fd, F_GETFL, 0);
        if (flags == SOCKET_ERROR_VALUE) {
            posix_ret = TranslateError(GET_ERRNO);
            return;
        }

        flags &= ~O_NONBLOCK;
        if (ctr_arg & 4) // O_NONBLOCK
            flags |= O_NONBLOCK;

        fd_info->second.blocking = ((ctr_arg & 4) == 0);

        int ret = ::fcntl(fd_info->second.socket_fd, F_SETFL, flags);
        if (ret == SOCKET_ERROR_VALUE) {
            posix_ret = TranslateError(GET_ERRNO);
            return;
        }
#endif
    } else {
        LOG_ERROR(Service_SOC, "Unsupported command ({}) in fcntl call", ctr_cmd);
        posix_ret = TranslateError(EINVAL); // TODO: Find the correct error
        return;
    }
}

void SOC_U::Listen(Kernel::HLERequestContext& ctx) {
    IPC::RequestParser rp(ctx, 0x03, 2, 2);
    u32 socket_handle = rp.Pop<u32>();
    auto fd_info = open_sockets.find(socket_handle);
    if (fd_info == open_sockets.end()) {
        IPC::RequestBuilder rb = rp.MakeBuilder(1, 0);
        rb.Push(ERR_INVALID_HANDLE);
        return;
    }
    u32 backlog = rp.Pop<u32>();
    rp.PopPID();

    s32 ret = ::listen(fd_info->second.socket_fd, backlog);
    if (ret != 0)
        ret = TranslateError(GET_ERRNO);

    IPC::RequestBuilder rb = rp.MakeBuilder(2, 0);
    rb.Push(RESULT_SUCCESS);
    rb.Push(ret);
}

void SOC_U::Accept(Kernel::HLERequestContext& ctx) {
    // TODO(Subv): Calling this function on a blocking socket will block the emu thread,
    // preventing graceful shutdown when closing the emulator, this can be fixed by always
    // performing nonblocking operations and spinlock until the data is available
    IPC::RequestParser rp(ctx, 0x04, 2, 2);
    const auto socket_handle = rp.Pop<u32>();
    auto fd_info = open_sockets.find(socket_handle);
    if (fd_info == open_sockets.end()) {
        IPC::RequestBuilder rb = rp.MakeBuilder(1, 0);
        rb.Push(ERR_INVALID_HANDLE);
        return;
    }
    [[maybe_unused]] const auto max_addr_len = static_cast<socklen_t>(rp.Pop<u32>());
    rp.PopPID();
    sockaddr addr;
    socklen_t addr_len = sizeof(addr);
    u32 ret = static_cast<u32>(::accept(fd_info->second.socket_fd, &addr, &addr_len));

    if (static_cast<s32>(ret) != SOCKET_ERROR_VALUE) {
        open_sockets[ret] = {ret, true};
    }

    CTRSockAddr ctr_addr;
    std::vector<u8> ctr_addr_buf(sizeof(ctr_addr));
    if (static_cast<s32>(ret) == SOCKET_ERROR_VALUE) {
        ret = TranslateError(GET_ERRNO);
    } else {
        ctr_addr = CTRSockAddr::FromPlatform(addr);
        std::memcpy(ctr_addr_buf.data(), &ctr_addr, sizeof(ctr_addr));
    }

    IPC::RequestBuilder rb = rp.MakeBuilder(2, 2);
    rb.Push(RESULT_SUCCESS);
    rb.Push(ret);
    rb.PushStaticBuffer(std::move(ctr_addr_buf), 0);
}

void SOC_U::GetHostId(Kernel::HLERequestContext& ctx) {
    IPC::RequestParser rp(ctx, 0x16, 0, 0);

    u32 host_id = 0;
    auto info = GetDefaultInterfaceInfo();
    if (info.has_value()) {
        host_id = info->address;
    }

    IPC::RequestBuilder rb = rp.MakeBuilder(2, 0);
    rb.Push(RESULT_SUCCESS);
    rb.Push(host_id);
}

void SOC_U::Close(Kernel::HLERequestContext& ctx) {
    IPC::RequestParser rp(ctx, 0x0B, 1, 2);
    u32 socket_handle = rp.Pop<u32>();
    auto fd_info = open_sockets.find(socket_handle);
    if (fd_info == open_sockets.end()) {
        IPC::RequestBuilder rb = rp.MakeBuilder(1, 0);
        rb.Push(ERR_INVALID_HANDLE);
        return;
    }
    rp.PopPID();

    s32 ret = 0;

    ret = closesocket(fd_info->second.socket_fd);

    open_sockets.erase(socket_handle);

    if (ret != 0)
        ret = TranslateError(GET_ERRNO);

    IPC::RequestBuilder rb = rp.MakeBuilder(2, 0);
    rb.Push(RESULT_SUCCESS);
    rb.Push(ret);
}

void SOC_U::SendToOther(Kernel::HLERequestContext& ctx) {
    IPC::RequestParser rp(ctx, 0x09, 4, 6);
    const u32 socket_handle = rp.Pop<u32>();
    const auto fd_info = open_sockets.find(socket_handle);
    if (fd_info == open_sockets.end()) {
        IPC::RequestBuilder rb = rp.MakeBuilder(1, 0);
        rb.Push(ERR_INVALID_HANDLE);
        return;
    }
    const u32 len = rp.Pop<u32>();
    const u32 flags = rp.Pop<u32>();
    const u32 addr_len = rp.Pop<u32>();
    rp.PopPID();
    const auto dest_addr_buffer = rp.PopStaticBuffer();

    auto input_mapped_buff = rp.PopMappedBuffer();
    std::vector<u8> input_buff(len);
    input_mapped_buff.Read(input_buff.data(), 0,
                           std::min(input_mapped_buff.GetSize(), static_cast<size_t>(len)));

    s32 ret = -1;
    if (addr_len > 0) {
        CTRSockAddr ctr_dest_addr;
        std::memcpy(&ctr_dest_addr, dest_addr_buffer.data(), sizeof(ctr_dest_addr));
        sockaddr dest_addr = CTRSockAddr::ToPlatform(ctr_dest_addr);
        ret = ::sendto(fd_info->second.socket_fd, reinterpret_cast<const char*>(input_buff.data()),
                       len, flags, &dest_addr, sizeof(dest_addr));
    } else {
        ret = ::sendto(fd_info->second.socket_fd, reinterpret_cast<const char*>(input_buff.data()),
                       len, flags, nullptr, 0);
    }

    if (ret == SOCKET_ERROR_VALUE) {
        ret = TranslateError(GET_ERRNO);
    }

    IPC::RequestBuilder rb = rp.MakeBuilder(2, 0);
    rb.Push(RESULT_SUCCESS);
    rb.Push(ret);
}

void SOC_U::SendTo(Kernel::HLERequestContext& ctx) {
    IPC::RequestParser rp(ctx, 0x0A, 4, 6);
    u32 socket_handle = rp.Pop<u32>();
    auto fd_info = open_sockets.find(socket_handle);
    if (fd_info == open_sockets.end()) {
        IPC::RequestBuilder rb = rp.MakeBuilder(1, 0);
        rb.Push(ERR_INVALID_HANDLE);
        return;
    }
    u32 len = rp.Pop<u32>();
    u32 flags = rp.Pop<u32>();
    u32 addr_len = rp.Pop<u32>();
    rp.PopPID();
    auto input_buff = rp.PopStaticBuffer();
    auto dest_addr_buff = rp.PopStaticBuffer();

    s32 ret = -1;
    if (addr_len > 0) {
        CTRSockAddr ctr_dest_addr;
        std::memcpy(&ctr_dest_addr, dest_addr_buff.data(), sizeof(ctr_dest_addr));
        sockaddr dest_addr = CTRSockAddr::ToPlatform(ctr_dest_addr);
        ret = ::sendto(fd_info->second.socket_fd, reinterpret_cast<const char*>(input_buff.data()),
                       len, flags, &dest_addr, sizeof(dest_addr));
    } else {
        ret = ::sendto(fd_info->second.socket_fd, reinterpret_cast<const char*>(input_buff.data()),
                       len, flags, nullptr, 0);
    }

    if (ret == SOCKET_ERROR_VALUE)
        ret = TranslateError(GET_ERRNO);

    IPC::RequestBuilder rb = rp.MakeBuilder(2, 0);
    rb.Push(RESULT_SUCCESS);
    rb.Push(ret);
}

void SOC_U::RecvFromOther(Kernel::HLERequestContext& ctx) {
    IPC::RequestParser rp(ctx, 0x7, 4, 4);
    u32 socket_handle = rp.Pop<u32>();
    auto fd_info = open_sockets.find(socket_handle);
    if (fd_info == open_sockets.end()) {
        IPC::RequestBuilder rb = rp.MakeBuilder(1, 0);
        rb.Push(ERR_INVALID_HANDLE);
        return;
    }
    u32 len = rp.Pop<u32>();
    u32 flags = rp.Pop<u32>();
    u32 addr_len = rp.Pop<u32>();
    rp.PopPID();
    auto& buffer = rp.PopMappedBuffer();

    CTRSockAddr ctr_src_addr;
    std::vector<u8> output_buff(len);
    std::vector<u8> addr_buff(sizeof(ctr_src_addr));
    sockaddr src_addr;
    socklen_t src_addr_len = sizeof(src_addr);

    s32 ret = -1;
    if (fd_info->second.blocking) {
        PreTimerAdjust();
    }

    if (addr_len > 0) {
        ret = ::recvfrom(fd_info->second.socket_fd, reinterpret_cast<char*>(output_buff.data()),
                         len, flags, &src_addr, &src_addr_len);
        if (ret >= 0 && src_addr_len > 0) {
            ctr_src_addr = CTRSockAddr::FromPlatform(src_addr);
            std::memcpy(addr_buff.data(), &ctr_src_addr, sizeof(ctr_src_addr));
        }
    } else {
        ret = ::recvfrom(fd_info->second.socket_fd, reinterpret_cast<char*>(output_buff.data()),
                         len, flags, NULL, 0);
        addr_buff.resize(0);
    }
    if (fd_info->second.blocking) {
        PostTimerAdjust(ctx, "RecvFromOther");
    }
    if (ret == SOCKET_ERROR_VALUE) {
        ret = TranslateError(GET_ERRNO);
    } else {
        buffer.Write(output_buff.data(), 0, ret);
    }

    IPC::RequestBuilder rb = rp.MakeBuilder(2, 4);
    rb.Push(RESULT_SUCCESS);
    rb.Push(ret);
    rb.PushStaticBuffer(std::move(addr_buff), 0);
    rb.PushMappedBuffer(buffer);
}

void SOC_U::RecvFrom(Kernel::HLERequestContext& ctx) {
    // TODO(Subv): Calling this function on a blocking socket will block the emu thread,
    // preventing graceful shutdown when closing the emulator, this can be fixed by always
    // performing nonblocking operations and spinlock until the data is available
    IPC::RequestParser rp(ctx, 0x08, 4, 2);
    u32 socket_handle = rp.Pop<u32>();
    auto fd_info = open_sockets.find(socket_handle);
    if (fd_info == open_sockets.end()) {
        IPC::RequestBuilder rb = rp.MakeBuilder(1, 0);
        rb.Push(ERR_INVALID_HANDLE);
        return;
    }
    u32 len = rp.Pop<u32>();
    u32 flags = rp.Pop<u32>();
    u32 addr_len = rp.Pop<u32>();
    rp.PopPID();

    CTRSockAddr ctr_src_addr;
    std::vector<u8> output_buff(len);
    std::vector<u8> addr_buff(addr_len);
    sockaddr src_addr;
    socklen_t src_addr_len = sizeof(src_addr);

    s32 ret = -1;
    if (fd_info->second.blocking) {
        PreTimerAdjust();
    }
    if (addr_len > 0) {
        // Only get src adr if input adr available
        ret = ::recvfrom(fd_info->second.socket_fd, reinterpret_cast<char*>(output_buff.data()),
                         len, flags, &src_addr, &src_addr_len);
        if (ret >= 0 && src_addr_len > 0) {
            ctr_src_addr = CTRSockAddr::FromPlatform(src_addr);
            std::memcpy(addr_buff.data(), &ctr_src_addr, addr_len);
        }
    } else {
        ret = ::recvfrom(fd_info->second.socket_fd, reinterpret_cast<char*>(output_buff.data()),
                         len, flags, NULL, 0);
        addr_buff.resize(0);
    }
    if (fd_info->second.blocking) {
        PostTimerAdjust(ctx, "RecvFrom");
    }

    s32 total_received = ret;
    if (ret == SOCKET_ERROR_VALUE) {
        ret = TranslateError(GET_ERRNO);
        total_received = 0;
    }

    // Write only the data we received to avoid overwriting parts of the buffer with zeros
    output_buff.resize(total_received);

    IPC::RequestBuilder rb = rp.MakeBuilder(3, 4);
    rb.Push(RESULT_SUCCESS);
    rb.Push(ret);
    rb.Push(total_received);
    rb.PushStaticBuffer(std::move(output_buff), 0);
    rb.PushStaticBuffer(std::move(addr_buff), 1);
}

void SOC_U::Poll(Kernel::HLERequestContext& ctx) {
    IPC::RequestParser rp(ctx, 0x14, 2, 4);
    u32 nfds = rp.Pop<u32>();
    s32 timeout = rp.Pop<s32>();
    rp.PopPID();
    auto input_fds = rp.PopStaticBuffer();

    std::vector<CTRPollFD> ctr_fds(nfds);
    std::memcpy(ctr_fds.data(), input_fds.data(), nfds * sizeof(CTRPollFD));

    // The 3ds_pollfd and the pollfd structures may be different (Windows/Linux have different
    // sizes)
    // so we have to copy the data in order
    std::vector<pollfd> platform_pollfd(nfds);
    for (u32 i = 0; i < nfds; i++) {
        platform_pollfd[i] = CTRPollFD::ToPlatform(*this, ctr_fds[i]);
    }

    if (timeout) {
        PreTimerAdjust();
    }
    s32 ret = ::poll(platform_pollfd.data(), nfds, timeout);
    if (timeout) {
        PostTimerAdjust(ctx, "Poll");
    }

    // Now update the output 3ds_pollfd structure
    for (u32 i = 0; i < nfds; i++) {
        ctr_fds[i] = CTRPollFD::FromPlatform(*this, platform_pollfd[i]);
    }

    std::vector<u8> output_fds(nfds * sizeof(CTRPollFD));
    std::memcpy(output_fds.data(), ctr_fds.data(), nfds * sizeof(CTRPollFD));

    if (ret == SOCKET_ERROR_VALUE) {
        int err = GET_ERRNO;
        LOG_ERROR(Service_SOC, "Socket error: {}", err);

        ret = TranslateError(GET_ERRNO);
    }

    IPC::RequestBuilder rb = rp.MakeBuilder(2, 2);
    rb.Push(RESULT_SUCCESS);
    rb.Push(ret);
    rb.PushStaticBuffer(std::move(output_fds), 0);
}

void SOC_U::GetSockName(Kernel::HLERequestContext& ctx) {
    IPC::RequestParser rp(ctx, 0x17, 2, 2);
    const auto socket_handle = rp.Pop<u32>();
    auto fd_info = open_sockets.find(socket_handle);
    if (fd_info == open_sockets.end()) {
        IPC::RequestBuilder rb = rp.MakeBuilder(1, 0);
        rb.Push(ERR_INVALID_HANDLE);
        return;
    }
    [[maybe_unused]] const auto max_addr_len = rp.Pop<u32>();
    rp.PopPID();

    sockaddr dest_addr;
    socklen_t dest_addr_len = sizeof(dest_addr);
    s32 ret = ::getsockname(fd_info->second.socket_fd, &dest_addr, &dest_addr_len);

    CTRSockAddr ctr_dest_addr = CTRSockAddr::FromPlatform(dest_addr);
    std::vector<u8> dest_addr_buff(sizeof(ctr_dest_addr));
    std::memcpy(dest_addr_buff.data(), &ctr_dest_addr, sizeof(ctr_dest_addr));

    if (ret != 0)
        ret = TranslateError(GET_ERRNO);

    IPC::RequestBuilder rb = rp.MakeBuilder(2, 2);
    rb.Push(RESULT_SUCCESS);
    rb.Push(ret);
    rb.PushStaticBuffer(std::move(dest_addr_buff), 0);
}

void SOC_U::Shutdown(Kernel::HLERequestContext& ctx) {
    IPC::RequestParser rp(ctx, 0x0C, 2, 2);
    u32 socket_handle = rp.Pop<u32>();
    auto fd_info = open_sockets.find(socket_handle);
    if (fd_info == open_sockets.end()) {
        IPC::RequestBuilder rb = rp.MakeBuilder(1, 0);
        rb.Push(ERR_INVALID_HANDLE);
        return;
    }
    s32 how = rp.Pop<s32>();
    rp.PopPID();

    s32 ret = ::shutdown(fd_info->second.socket_fd, how);
    if (ret != 0)
        ret = TranslateError(GET_ERRNO);
    IPC::RequestBuilder rb = rp.MakeBuilder(2, 0);
    rb.Push(RESULT_SUCCESS);
    rb.Push(ret);
}

void SOC_U::GetHostByName(Kernel::HLERequestContext& ctx) {
    IPC::RequestParser rp(ctx, 0x0D, 2, 2);
    [[maybe_unused]] u32 name_len = rp.Pop<u32>();
    [[maybe_unused]] u32 out_buf_len = rp.Pop<u32>();
    auto host_name = rp.PopStaticBuffer();

    struct hostent* result = ::gethostbyname(reinterpret_cast<char*>(host_name.data()));

    std::vector<u8> hbn_data_out(sizeof(HostByNameData));
    HostByNameData& hbn_data = *reinterpret_cast<HostByNameData*>(hbn_data_out.data());
    int ret = 0;

    if (result) {
        hbn_data.addr_type = result->h_addrtype;
        hbn_data.addr_len = result->h_length;
        std::strncpy(hbn_data.hName.data(), result->h_name, 255);
        u16 count;
        for (count = 0; count < HostByNameData::max_entries; count++) {
            char* curr = result->h_aliases[count];
            if (!curr) {
                break;
            }
            std::strncpy(hbn_data.aliases[count].data(), curr, 255);
        }
        hbn_data.alias_count = count;
        for (count = 0; count < HostByNameData::max_entries; count++) {
            char* curr = result->h_addr_list[count];
            if (!curr) {
                break;
            }
            std::memcpy(hbn_data.addresses[count].data(), curr, result->h_length);
        }
        hbn_data.addr_count = count;
    } else {
        ret = -1;
    }

    IPC::RequestBuilder rb = rp.MakeBuilder(2, 2);
    rb.Push(RESULT_SUCCESS);
    rb.Push(ret);
    rb.PushStaticBuffer(std::move(hbn_data_out), 0);
}

void SOC_U::GetPeerName(Kernel::HLERequestContext& ctx) {
    IPC::RequestParser rp(ctx, 0x18, 2, 2);
    const auto socket_handle = rp.Pop<u32>();
    auto fd_info = open_sockets.find(socket_handle);
    if (fd_info == open_sockets.end()) {
        IPC::RequestBuilder rb = rp.MakeBuilder(1, 0);
        rb.Push(ERR_INVALID_HANDLE);
        return;
    }
    [[maybe_unused]] const auto max_addr_len = rp.Pop<u32>();
    rp.PopPID();

    sockaddr dest_addr;
    socklen_t dest_addr_len = sizeof(dest_addr);
    const int ret = ::getpeername(fd_info->second.socket_fd, &dest_addr, &dest_addr_len);

    CTRSockAddr ctr_dest_addr = CTRSockAddr::FromPlatform(dest_addr);
    std::vector<u8> dest_addr_buff(sizeof(ctr_dest_addr));
    std::memcpy(dest_addr_buff.data(), &ctr_dest_addr, sizeof(ctr_dest_addr));

    int result = 0;
    if (ret != 0) {
        result = TranslateError(GET_ERRNO);
    }

    IPC::RequestBuilder rb = rp.MakeBuilder(2, 2);
    rb.Push(RESULT_SUCCESS);
    rb.Push(result);
    rb.PushStaticBuffer(std::move(dest_addr_buff), 0);
}

void SOC_U::Connect(Kernel::HLERequestContext& ctx) {
    // TODO(Subv): Calling this function on a blocking socket will block the emu thread,
    // preventing graceful shutdown when closing the emulator, this can be fixed by always
    // performing nonblocking operations and spinlock until the data is available
    IPC::RequestParser rp(ctx, 0x06, 2, 4);
    const auto socket_handle = rp.Pop<u32>();
    auto fd_info = open_sockets.find(socket_handle);
    if (fd_info == open_sockets.end()) {
        IPC::RequestBuilder rb = rp.MakeBuilder(1, 0);
        rb.Push(ERR_INVALID_HANDLE);
        return;
    }
    [[maybe_unused]] const auto input_addr_len = rp.Pop<u32>();
    rp.PopPID();
    auto input_addr_buf = rp.PopStaticBuffer();

    CTRSockAddr ctr_input_addr;
    std::memcpy(&ctr_input_addr, input_addr_buf.data(), sizeof(ctr_input_addr));

    sockaddr input_addr = CTRSockAddr::ToPlatform(ctr_input_addr);
    if (fd_info->second.blocking) {
        PreTimerAdjust();
    }
    s32 ret = ::connect(fd_info->second.socket_fd, &input_addr, sizeof(input_addr));
    if (fd_info->second.blocking) {
        PostTimerAdjust(ctx, "Connect");
    }
    if (ret != 0)
        ret = TranslateError(GET_ERRNO);

    IPC::RequestBuilder rb = rp.MakeBuilder(2, 0);
    rb.Push(RESULT_SUCCESS);
    rb.Push(ret);
}

void SOC_U::InitializeSockets(Kernel::HLERequestContext& ctx) {
    // TODO(Subv): Implement
    IPC::RequestParser rp(ctx, 0x01, 1, 4);
    [[maybe_unused]] const auto memory_block_size = rp.Pop<u32>();
    rp.PopPID();
    rp.PopObject<Kernel::SharedMemory>();

    IPC::RequestBuilder rb = rp.MakeBuilder(1, 0);
    rb.Push(RESULT_SUCCESS);
}

void SOC_U::ShutdownSockets(Kernel::HLERequestContext& ctx) {
    // TODO(Subv): Implement
    IPC::RequestParser rp(ctx, 0x19, 0, 0);
    CleanupSockets();

    IPC::RequestBuilder rb = rp.MakeBuilder(1, 0);
    rb.Push(RESULT_SUCCESS);
}

void SOC_U::GetSockOpt(Kernel::HLERequestContext& ctx) {
    IPC::RequestParser rp(ctx, 0x11, 4, 2);
    u32 socket_handle = rp.Pop<u32>();
    auto fd_info = open_sockets.find(socket_handle);
    if (fd_info == open_sockets.end()) {
        IPC::RequestBuilder rb = rp.MakeBuilder(1, 0);
        rb.Push(ERR_INVALID_HANDLE);
        return;
    }
    u32 level = rp.Pop<u32>();
    // Translate 3DS SOL_SOCKET to platform SOL_SOCKET
    if (level == SOC_SOL_SOCKET) {
        level = SOL_SOCKET;
    }
    s32 optname = rp.Pop<s32>();
    socklen_t optlen = static_cast<socklen_t>(rp.Pop<u32>());
    rp.PopPID();

    s32 err = 0;

    std::vector<u8> optval(optlen);

    if (optname < 0) {
#ifdef _WIN32
        err = WSAEINVAL;
#else
        err = EINVAL;
#endif
    } else {
        char* optval_data = reinterpret_cast<char*>(optval.data());
        err = ::getsockopt(fd_info->second.socket_fd, level, TranslateSockOpt(optname), optval_data,
                           &optlen);
        if (err == SOCKET_ERROR_VALUE) {
            err = TranslateError(GET_ERRNO);
        }
    }

    IPC::RequestBuilder rb = rp.MakeBuilder(3, 2);
    rb.Push(RESULT_SUCCESS);
    rb.Push(err);
    rb.Push(static_cast<u32>(optlen));
    rb.PushStaticBuffer(std::move(optval), 0);
}

void SOC_U::SetSockOpt(Kernel::HLERequestContext& ctx) {
    IPC::RequestParser rp(ctx, 0x12, 4, 4);
    const auto socket_handle = rp.Pop<u32>();
    auto fd_info = open_sockets.find(socket_handle);
    if (fd_info == open_sockets.end()) {
        IPC::RequestBuilder rb = rp.MakeBuilder(1, 0);
        rb.Push(ERR_INVALID_HANDLE);
        return;
    }
    auto level = rp.Pop<u32>();
    // Translate 3DS SOL_SOCKET to platform SOL_SOCKET
    if (level == SOC_SOL_SOCKET) {
        level = SOL_SOCKET;
    }
    const auto optname = rp.Pop<s32>();
    [[maybe_unused]] const auto optlen = static_cast<socklen_t>(rp.Pop<u32>());
    rp.PopPID();
    const auto optval = rp.PopStaticBuffer();

    s32 err = 0;

    if (optname < 0) {
#ifdef _WIN32
        err = WSAEINVAL;
#else
        err = EINVAL;
#endif
    } else {
        const char* optval_data = reinterpret_cast<const char*>(optval.data());
        err = static_cast<u32>(::setsockopt(fd_info->second.socket_fd, level,
                                            TranslateSockOpt(optname), optval_data,
                                            static_cast<socklen_t>(optval.size())));
        if (err == SOCKET_ERROR_VALUE) {
            err = TranslateError(GET_ERRNO);
        }
    }

    IPC::RequestBuilder rb = rp.MakeBuilder(2, 0);
    rb.Push(RESULT_SUCCESS);
    rb.Push(err);
}

void SOC_U::GetNetworkOpt(Kernel::HLERequestContext& ctx) {
    IPC::RequestParser rp(ctx, 0x1A, 3, 0);
    u32 level = rp.Pop<u32>();
    u32 opt_name = rp.Pop<u32>();
    u32 opt_len = rp.Pop<u32>();
    std::vector<u8> opt_data(opt_len);

    u32 err = SOC_ERR_INAVLID_ENUM_VALUE;

    /// Only available level is SOC_SOL_CONFIG, any other value returns an error
    if (level == SOC_SOL_CONFIG) {
        switch (static_cast<NetworkOpt>(opt_name)) {
        case NetworkOpt::NETOPT_MAC_ADDRESS: {
            if (opt_len >= 6) {
                u8 fake_mac[6] = {0};
                memcpy(opt_data.data(), fake_mac, sizeof(fake_mac));
            }
            LOG_WARNING(Service_SOC, "(STUBBED) called, level={} opt_name={}", level, opt_name);
            err = 0;
        } break;
        case NetworkOpt::NETOPT_IP_INFO: {
            if (opt_len >= sizeof(InterfaceInfo)) {
                InterfaceInfo& out_info = *reinterpret_cast<InterfaceInfo*>(opt_data.data());
                auto info = GetDefaultInterfaceInfo();
                if (info.has_value()) {
                    out_info = info.value();
                }
            }
            // Extra data not used normally, takes 0xC bytes more
            if (opt_len >= sizeof(InterfaceInfo) + 0xC) {
                LOG_ERROR(Service_SOC, "(STUBBED) called, level={} opt_name={} opt_len >= 24",
                          level, opt_name);
            }
            err = 0;
        } break;
        default:
            LOG_ERROR(Service_SOC, "(STUBBED) called, level={} opt_name={}", level, opt_name);
            break;
        }
    } else {
        LOG_ERROR(Service_SOC, "Unknown level={}", level);
    }

    if (err != 0) {
        opt_data.resize(0);
        opt_len = 0;
    }

    IPC::RequestBuilder rb = rp.MakeBuilder(3, 2);
    rb.Push(RESULT_SUCCESS);
    rb.Push(err);
    rb.Push(static_cast<u32>(opt_len));
    rb.PushStaticBuffer(std::move(opt_data), 0);
}

void SOC_U::GetAddrInfoImpl(Kernel::HLERequestContext& ctx) {
    IPC::RequestParser rp(ctx, 0x0F, 4, 6);
    u32 node_length = rp.Pop<u32>();
    u32 service_length = rp.Pop<u32>();
    u32 hints_size = rp.Pop<u32>();
    u32 out_size = rp.Pop<u32>();
    auto node = rp.PopStaticBuffer();
    auto service = rp.PopStaticBuffer();
    auto hints_buff = rp.PopStaticBuffer();

    const char* node_data = node_length > 0 ? reinterpret_cast<const char*>(node.data()) : nullptr;
    const char* service_data =
        service_length > 0 ? reinterpret_cast<const char*>(service.data()) : nullptr;

    s32 ret = -1;
    addrinfo* out = nullptr;
    if (hints_size > 0) {
        CTRAddrInfo ctr_hints;
        std::memcpy(&ctr_hints, hints_buff.data(), hints_size);
        // Only certain fields are meaningful in hints, copy them manually
        addrinfo hints = {};
        hints.ai_flags = ctr_hints.ai_flags;
        hints.ai_family = ctr_hints.ai_family;
        hints.ai_socktype = ctr_hints.ai_socktype;
        hints.ai_protocol = ctr_hints.ai_protocol;
        ret = getaddrinfo(node_data, service_data, &hints, &out);
    } else {
        ret = getaddrinfo(node_data, service_data, nullptr, &out);
    }

    std::vector<u8> out_buff(out_size);
    u32 count = 0;

    if (ret == SOCKET_ERROR_VALUE) {
        ret = TranslateError(GET_ERRNO);
        out_buff.resize(0);
    } else {
        std::size_t pos = 0;
        addrinfo* cur = out;
        while (cur != nullptr) {
            if (pos <= out_size - sizeof(CTRAddrInfo)) {
                // According to 3dbrew, this function fills whatever it can and does not error even
                // if the buffer is not big enough. However the count returned is always correct.
                CTRAddrInfo ctr_addr = CTRAddrInfo::FromPlatform(*cur);
                std::memcpy(out_buff.data() + pos, &ctr_addr, sizeof(ctr_addr));
                pos += sizeof(ctr_addr);
            }
            cur = cur->ai_next;
            count++;
        }
        if (out != nullptr)
            freeaddrinfo(out);
    }

    IPC::RequestBuilder rb = rp.MakeBuilder(3, 2);
    rb.Push(RESULT_SUCCESS);
    rb.Push(ret);
    rb.Push(count);
    rb.PushStaticBuffer(std::move(out_buff), 0);
}

void SOC_U::GetNameInfoImpl(Kernel::HLERequestContext& ctx) {
    IPC::RequestParser rp(ctx, 0x10, 4, 2);
    u32 socklen = rp.Pop<u32>();
    u32 hostlen = rp.Pop<u32>();
    u32 servlen = rp.Pop<u32>();
    s32 flags = rp.Pop<s32>();
    auto sa_buff = rp.PopStaticBuffer();

    CTRSockAddr ctr_sa;
    std::memcpy(&ctr_sa, sa_buff.data(), socklen);
    sockaddr sa = CTRSockAddr::ToPlatform(ctr_sa);

    std::vector<u8> host(hostlen);
    std::vector<u8> serv(servlen);
    char* host_data = hostlen > 0 ? reinterpret_cast<char*>(host.data()) : nullptr;
    char* serv_data = servlen > 0 ? reinterpret_cast<char*>(serv.data()) : nullptr;

    s32 ret = getnameinfo(&sa, sizeof(sa), host_data, hostlen, serv_data, servlen, flags);
    if (ret == SOCKET_ERROR_VALUE) {
        ret = TranslateError(GET_ERRNO);
    }

    IPC::RequestBuilder rb = rp.MakeBuilder(2, 4);
    rb.Push(RESULT_SUCCESS);
    rb.Push(ret);
    rb.PushStaticBuffer(std::move(host), 0);
    rb.PushStaticBuffer(std::move(serv), 1);
}

SOC_U::SOC_U() : ServiceFramework("soc:U") {
    static const FunctionInfo functions[] = {
        {0x00010044, &SOC_U::InitializeSockets, "InitializeSockets"},
        {0x000200C2, &SOC_U::Socket, "Socket"},
        {0x00030082, &SOC_U::Listen, "Listen"},
        {0x00040082, &SOC_U::Accept, "Accept"},
        {0x00050084, &SOC_U::Bind, "Bind"},
        {0x00060084, &SOC_U::Connect, "Connect"},
        {0x00070104, &SOC_U::RecvFromOther, "recvfrom_other"},
        {0x00080102, &SOC_U::RecvFrom, "RecvFrom"},
        {0x00090106, &SOC_U::SendToOther, "SendToOther"},
        {0x000A0106, &SOC_U::SendTo, "SendTo"},
        {0x000B0042, &SOC_U::Close, "Close"},
        {0x000C0082, &SOC_U::Shutdown, "Shutdown"},
        {0x000D0082, &SOC_U::GetHostByName, "GetHostByName"},
        {0x000E00C2, nullptr, "GetHostByAddr"},
        {0x000F0106, &SOC_U::GetAddrInfoImpl, "GetAddrInfo"},
        {0x00100102, &SOC_U::GetNameInfoImpl, "GetNameInfo"},
        {0x00110102, &SOC_U::GetSockOpt, "GetSockOpt"},
        {0x00120104, &SOC_U::SetSockOpt, "SetSockOpt"},
        {0x001300C2, &SOC_U::Fcntl, "Fcntl"},
        {0x00140084, &SOC_U::Poll, "Poll"},
        {0x00150042, nullptr, "SockAtMark"},
        {0x00160000, &SOC_U::GetHostId, "GetHostId"},
        {0x00170082, &SOC_U::GetSockName, "GetSockName"},
        {0x00180082, &SOC_U::GetPeerName, "GetPeerName"},
        {0x00190000, &SOC_U::ShutdownSockets, "ShutdownSockets"},
        {0x001A00C0, &SOC_U::GetNetworkOpt, "GetNetworkOpt"},
        {0x001B0040, nullptr, "ICMPSocket"},
        {0x001C0104, nullptr, "ICMPPing"},
        {0x001D0040, nullptr, "ICMPCancel"},
        {0x001E0040, nullptr, "ICMPClose"},
        {0x001F0040, nullptr, "GetResolverInfo"},
        {0x00210002, nullptr, "CloseSockets"},
        {0x00230040, nullptr, "AddGlobalSocket"},
    };

    RegisterHandlers(functions);

#ifdef _WIN32
    WSADATA data;
    WSAStartup(MAKEWORD(2, 2), &data);
#endif
}

SOC_U::~SOC_U() {
    CleanupSockets();
#ifdef _WIN32
    WSACleanup();
#endif
}

std::optional<SOC_U::InterfaceInfo> SOC_U::GetDefaultInterfaceInfo() {
    if (this->interface_info_cached) {
        return InterfaceInfo(this->interface_info);
    }

    InterfaceInfo ret;
    s64 sock_fd = -1;
    bool interface_found = false;
    struct sockaddr_in s_in = {.sin_family = AF_INET, .sin_port = htons(53), .sin_addr = {}};
    s_in.sin_addr.s_addr = inet_addr("8.8.8.8");
    socklen_t s_info_len = sizeof(struct sockaddr_in);
    sockaddr_in s_info;

    if ((sock_fd = ::socket(AF_INET, SOCK_STREAM, 0)) == -1) {
        return std::nullopt;
    }

    if (::connect(sock_fd, (struct sockaddr*)(&s_in), sizeof(struct sockaddr_in)) != 0) {
        closesocket(sock_fd);
        return std::nullopt;
    }

    if (::getsockname(sock_fd, (struct sockaddr*)&s_info, &s_info_len) != 0 ||
        s_info_len != sizeof(struct sockaddr_in)) {
        closesocket(sock_fd);
        return std::nullopt;
    }
    closesocket(sock_fd);

#ifdef _WIN32
    sock_fd = WSASocket(AF_INET, SOCK_DGRAM, 0, 0, 0, 0);
    if (sock_fd == SOCKET_ERROR) {
        return std::nullopt;
    }

    const int max_interfaces = 100;
    std::vector<INTERFACE_INFO> interface_list_vec(max_interfaces);
    INTERFACE_INFO* interface_list = reinterpret_cast<INTERFACE_INFO*>(interface_list_vec.data());
    unsigned long bytes_used;
    if (WSAIoctl(sock_fd, SIO_GET_INTERFACE_LIST, 0, 0, interface_list,
                 max_interfaces * sizeof(INTERFACE_INFO), &bytes_used, 0, 0) == SOCKET_ERROR) {
        closesocket(sock_fd);
        return std::nullopt;
    }
    closesocket(sock_fd);

    int num_interfaces = bytes_used / sizeof(INTERFACE_INFO);
    for (int i = 0; i < num_interfaces; i++) {
        if (((sockaddr*)&(interface_list[i].iiAddress))->sa_family == AF_INET &&
            memcmp(&((sockaddr_in*)&(interface_list[i].iiAddress))->sin_addr.s_addr,
                   &s_info.sin_addr.s_addr, sizeof(s_info.sin_addr.s_addr)) == 0) {
            ret.address = ((sockaddr_in*)&(interface_list[i].iiAddress))->sin_addr.s_addr;
            ret.netmask = ((sockaddr_in*)&(interface_list[i].iiNetmask))->sin_addr.s_addr;
            ret.broadcast =
                ((sockaddr_in*)&(interface_list[i].iiBroadcastAddress))->sin_addr.s_addr;
            interface_found = true;
            {
                char address[16] = {0}, netmask[16] = {0}, broadcast[16] = {0};
                std::strncpy(address,
                             inet_ntoa(((sockaddr_in*)&(interface_list[i].iiAddress))->sin_addr),
                             sizeof(address) - 1);
                std::strncpy(netmask,
                             inet_ntoa(((sockaddr_in*)&(interface_list[i].iiNetmask))->sin_addr),
                             sizeof(netmask) - 1);
                std::strncpy(
                    broadcast,
                    inet_ntoa(((sockaddr_in*)&(interface_list[i].iiBroadcastAddress))->sin_addr),
                    sizeof(broadcast) - 1);

                LOG_DEBUG(Service_SOC, "Found interface: (addr: {}, netmask: {}, broadcast: {})",
                          address, netmask, broadcast);
            }
            break;
        }
    }
#else
    struct ifaddrs* ifaddr;
    struct ifaddrs* ifa;
    if (getifaddrs(&ifaddr) == -1) {
        return std::nullopt;
    }

    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr && ifa->ifa_addr->sa_family == AF_INET) {
            struct sockaddr_in* in_address = (struct sockaddr_in*)ifa->ifa_addr;
            struct sockaddr_in* in_netmask = (struct sockaddr_in*)ifa->ifa_netmask;
            struct sockaddr_in* in_broadcast = (struct sockaddr_in*)ifa->ifa_broadaddr;
            if (in_address->sin_addr.s_addr == s_info.sin_addr.s_addr) {
                ret.address = in_address->sin_addr.s_addr;
                ret.netmask = in_netmask->sin_addr.s_addr;
                ret.broadcast = in_broadcast->sin_addr.s_addr;
                interface_found = true;
                {
                    char address[16] = {0}, netmask[16] = {0}, broadcast[16] = {0};
                    std::strncpy(address, inet_ntoa(in_address->sin_addr), sizeof(address) - 1);
                    std::strncpy(netmask, inet_ntoa(in_netmask->sin_addr), sizeof(netmask) - 1);
                    std::strncpy(broadcast, inet_ntoa(in_broadcast->sin_addr),
                                 sizeof(broadcast) - 1);

                    LOG_DEBUG(Service_SOC,
                              "Found interface: (addr: {}, netmask: {}, broadcast: {})", address,
                              netmask, broadcast);
                }
            }
        }
    }
    freeifaddrs(ifaddr);
#endif // _WIN32
    if (interface_found) {
        this->interface_info = ret;
        this->interface_info_cached = true;
        return ret;
    } else {
        LOG_DEBUG(Service_SOC, "Interface not found");
        return std::nullopt;
    }
}

std::shared_ptr<SOC_U> GetService(Core::System& system) {
    return system.ServiceManager().GetService<SOC_U>("cfg:u");
}

void InstallInterfaces(Core::System& system) {
    auto& service_manager = system.ServiceManager();
    std::make_shared<SOC_U>()->InstallAsService(service_manager);
}

} // namespace Service::SOC
