// Copyright (C) Microsoft Corporation. All rights reserved.

#include "blockdev.h"
#include "util.h"
#include "common.h"

#include <linux/nbd.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>

#include <fcntl.h>
#include <unistd.h>
#include <cstring>
#include <cstdio>
#include <cstdint>
#include <arpa/inet.h>

// Network-to-host for 64-bit values (x86 is LE, NBD is big-endian)
static inline uint64_t Ntohll(uint64_t x) { return __builtin_bswap64(x); }

namespace {

#pragma pack(push, 1)
struct NBDRequest
{
    uint32_t Magic;
    uint16_t Flags;
    uint16_t Type;
    uint64_t Handle;
    uint64_t Offset;
    uint32_t Length;
};

struct NBDReply
{
    uint32_t Magic;
    uint32_t Error;
    uint64_t Handle;
};
#pragma pack(pop)

// Relay data from one fd to another
static bool RelayData(int FromFd, int ToFd, uint32_t Length)
{
    char buffer[65536];
    while (Length > 0)
    {
        uint32_t chunk = Length > sizeof(buffer) ? sizeof(buffer) : Length;
        int n = read(FromFd, buffer, chunk);
        if (n <= 0) return false;
        int remaining = n;
        char* ptr = buffer;
        while (remaining > 0)
        {
            int w = write(ToFd, ptr, remaining);
            if (w <= 0) return false;
            ptr += w;
            remaining -= w;
        }
        Length -= n;
    }
    return true;
}

// NBD protocol bridge: relays NBD traffic between a UNIX socket (connected to
// the kernel NBD module) and a vsock socket (connected to the Windows NBD server).
// The kernel NBD driver only supports AF_UNIX and AF_INET sockets, not AF_VSOCK,
// so this userspace bridge is required.
static void NbdBridgeDaemon(int UnixFd, int VsockFd)
{
    // The handshake was already consumed by SetupBlockDevice() before forking,
    // so the vsock socket is positioned at the first NBD request/reply exchange.
    // Proxy loop: forward NBD requests from kernel to Windows and replies back.
    while (true)
    {
        // Read NBD request from kernel (via UNIX socket)
        NBDRequest req;
        int n = read(UnixFd, &req, sizeof(req));
        if (n <= 0) break;

        // Forward request to Windows server
        if (write(VsockFd, &req, sizeof(req)) < 0) break;

        // For WRITE commands, the kernel sends data after the request
        uint32_t type = ntohs(req.Type);
        uint32_t length = ntohl(req.Length);
        if (type == 1 && length > 0) // NBD_CMD_WRITE
        {
            if (!RelayData(UnixFd, VsockFd, length)) break;
        }

        // Read NBD reply from Windows server
        NBDReply reply;
        if (read(VsockFd, &reply, sizeof(reply)) <= 0) break;

        // Forward reply to kernel
        if (write(UnixFd, &reply, sizeof(reply)) < 0) break;

        // For READ commands, the server sends data after the reply
        uint32_t error = ntohl(reply.Error);
        if (type == 0 && error == 0 && length > 0) // NBD_CMD_READ
        {
            if (!RelayData(VsockFd, UnixFd, length)) break;
        }

        // NBD_CMD_DISC: Windows closed the connection
        if (type == 2) break;
    }
}

} // anonymous namespace

std::string SetupBlockDevice(unsigned int VsockPort)
{
    LOG_INFO("Setting up block device via vsock port %u", VsockPort);

    // Ensure the NBD kernel module is loaded
    {
        int Status = -1;
        const char* Argv[] = {"/sbin/modprobe", "nbd", nullptr};
        if (UtilCreateProcessAndWait("/sbin/modprobe", Argv, &Status) < 0 || Status != 0)
        {
            LOG_ERROR("Failed to load nbd kernel module (status %d)", Status);
        }
    }

    // Connect to the Windows NBD block device server over vsock.
    // The Windows server immediately sends the old-style NBD handshake.
    wil::unique_fd vsockFd = UtilConnectVsock(VsockPort, true);
    if (!vsockFd)
    {
        LOG_ERROR("Failed to connect to vsock port %u", VsockPort);
        return {};
    }

    // Read the NBD handshake to get device size and consume it from the stream.
    uint64_t nbdMagic, cliservMagic, sizeNBO;
    uint32_t flagsNBO;
    char padding[124];

    auto ReadAll = [&](void* Buf, size_t Len) -> bool {
        char* ptr = static_cast<char*>(Buf);
        size_t remaining = Len;
        while (remaining > 0)
        {
            int n = read(vsockFd.get(), ptr, remaining);
            if (n <= 0) return false;
            ptr += n;
            remaining -= n;
        }
        return true;
    };

    if (!ReadAll(&nbdMagic, sizeof(nbdMagic)) ||
        !ReadAll(&cliservMagic, sizeof(cliservMagic)) ||
        !ReadAll(&sizeNBO, sizeof(sizeNBO)) ||
        !ReadAll(&flagsNBO, sizeof(flagsNBO)) ||
        !ReadAll(padding, sizeof(padding)))
    {
        LOG_ERROR("Failed to read NBD handshake");
        return {};
    }

    if (Ntohll(nbdMagic) != 0x956202b8c0e4d6d4ULL ||
        Ntohll(cliservMagic) != 0x49484156454F5054ULL)
    {
        LOG_ERROR("Invalid NBD handshake magic");
        return {};
    }

    uint64_t deviceSize = Ntohll(sizeNBO);
    uint32_t sectorSize = 512;

    LOG_INFO("NBD device size: %lu bytes, flags: 0x%x", (unsigned long)deviceSize, ntohl(flagsNBO));

    // Find a free NBD device (/dev/nbdX)
    int nbdFd = -1;
    int nbdIndex = 0;
    for (; nbdIndex < 16; nbdIndex++)
    {
        char path[32];
        snprintf(path, sizeof(path), "/dev/nbd%d", nbdIndex);
        nbdFd = open(path, O_RDWR);
        if (nbdFd < 0)
        {
            LOG_ERROR("Failed to open %s: %s", path, strerror(errno));
            return {};
        }

        if (ioctl(nbdFd, NBD_SET_BLKSIZE, sectorSize) == 0)
            break;

        close(nbdFd);
        nbdFd = -1;
    }

    if (nbdFd < 0)
    {
        LOG_ERROR("No free NBD device found");
        return {};
    }

    ioctl(nbdFd, NBD_SET_SIZE, deviceSize);
    ioctl(nbdFd, NBD_SET_BLKSIZE, sectorSize);

    // Create a UNIX socket pair for the kernel NBD connection.
    // The kernel NBD driver only supports AF_UNIX/AF_INET, not AF_VSOCK.
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) < 0)
    {
        LOG_ERROR("socketpair failed: %s", strerror(errno));
        close(nbdFd);
        return {};
    }

    // Pass sv[0] to the kernel NBD module
    if (ioctl(nbdFd, NBD_SET_SOCK, sv[0]) < 0)
    {
        LOG_ERROR("NBD_SET_SOCK failed: %s", strerror(errno));
        close(sv[0]);
        close(sv[1]);
        close(nbdFd);
        return {};
    }

    // Fork child process to handle NBD_DO_IT (blocks until disconnect).
    // The child then forks a grandchild to run the NBD bridge daemon
    // (which translates between UNIX socket and vsock).
    pid_t pid = fork();
    if (pid < 0)
    {
        LOG_ERROR("fork failed: %s", strerror(errno));
        ioctl(nbdFd, NBD_CLEAR_SOCK);
        close(sv[0]);
        close(sv[1]);
        close(nbdFd);
        return {};
    }

    if (pid == 0)
    {
        // Child process
        close(sv[0]); // kernel uses sv[0], we use sv[1]

        // Release vsock fd from unique_fd ownership (prevent double close)
        int rawVsockFd = vsockFd.release();

        // Fork grandchild for the NBD bridge daemon
        pid_t bridgePid = fork();
        if (bridgePid == 0)
        {
            // Grandchild: NBD bridge daemon
            NbdBridgeDaemon(sv[1], rawVsockFd);
            _exit(0);
        }

        if (bridgePid < 0)
        {
            LOG_ERROR("fork bridge failed: %s", strerror(errno));
            close(sv[1]);
            close(rawVsockFd);
            _exit(1);
        }

        // Child: block on NBD_DO_IT
        close(sv[1]);
        close(rawVsockFd);
        ioctl(nbdFd, NBD_DO_IT);
        ioctl(nbdFd, NBD_CLEAR_SOCK);
        close(nbdFd);
        _exit(0);
    }

    // Parent: close our copies of the fds
    close(sv[0]);
    close(sv[1]);
    close(nbdFd);
    vsockFd.reset();

    char devPath[32];
    snprintf(devPath, sizeof(devPath), "/dev/nbd%d", nbdIndex);
    LOG_INFO("Block device %s ready", devPath);
    return std::string(devPath);
}
