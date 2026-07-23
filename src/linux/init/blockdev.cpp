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

// Network-to-host / host-to-network for 64-bit values (x86 is LE, NBD is big-endian)
static inline uint64_t Htonll(uint64_t x) { return __builtin_bswap64(x); }
static inline uint64_t Ntohll(uint64_t x) { return __builtin_bswap64(x); }

std::string SetupBlockDevice(unsigned int VsockPort)
{
    LOG_INFO("Setting up block device via vsock port %u", VsockPort);

    // Connect to the Windows NBD block device server over vsock
    wil::unique_fd vsockFd = UtilConnectVsock(VsockPort, true);
    if (!vsockFd)
    {
        LOG_ERROR("Failed to connect to vsock port %u", VsockPort);
        return {};
    }

    // Read the NBD old-style handshake from the vsock connection.
    // The Windows server sends:
    //   uint64_t nbd_magic      (0x956202b8c0e4d6d4 big-endian)
    //   uint64_t cliserv_magic  (0x49484156454F5054 big-endian)
    //   uint64_t device_size    (big-endian)
    //   uint32_t flags          (big-endian)
    //   char     padding[124]
    // Total: 152 bytes.
    // The handshake data is consumed here so the kernel NBD module
    // (which does NOT read a handshake) gets a socket positioned at
    // the first NBD request.
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

    // Verify the NBD magic values
    if (Ntohll(nbdMagic) != 0x956202b8c0e4d6d4ULL ||
        Ntohll(cliservMagic) != 0x49484156454F5054ULL)
    {
        LOG_ERROR("Invalid NBD handshake magic");
        return {};
    }

    uint64_t deviceSize = Ntohll(sizeNBO);
    uint32_t flags = ntohl(flagsNBO);
    uint32_t sectorSize = 512;

    LOG_INFO("NBD device size: %lu bytes, flags: 0x%x", (unsigned long)deviceSize, flags);

    // Find a free NBD device
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

        // NBD_SET_BLKSIZE fails if device is already in use (connected)
        if (ioctl(nbdFd, NBD_SET_BLKSIZE, sectorSize) == 0)
        {
            break;
        }
        close(nbdFd);
        nbdFd = -1;
    }

    if (nbdFd < 0)
    {
        LOG_ERROR("No free NBD device found");
        return {};
    }

    // Set up the NBD device
    ioctl(nbdFd, NBD_SET_SIZE, deviceSize);
    ioctl(nbdFd, NBD_SET_BLKSIZE, sectorSize);

    // Pass the vsock socket directly to the kernel's NBD module.
    // The kernel sends NBD requests and reads NBD replies on this socket.
    // NBD_SET_SOCK does fget() on the socket, so the kernel holds its
    // own reference independent of our fd.
    if (ioctl(nbdFd, NBD_SET_SOCK, vsockFd.get()) < 0)
    {
        LOG_ERROR("NBD_SET_SOCK failed: %s", strerror(errno));
        close(nbdFd);
        return {};
    }

    // Fork: child blocks in NBD_DO_IT (runs kernel NBD threads),
    // parent returns the device path immediately.
    pid_t pid = fork();
    if (pid < 0)
    {
        LOG_ERROR("fork failed: %s", strerror(errno));
        ioctl(nbdFd, NBD_CLEAR_SOCK);
        close(nbdFd);
        return {};
    }

    if (pid == 0)
    {
        // Child: blocks until the NBD connection is terminated
        ioctl(nbdFd, NBD_DO_IT);
        ioctl(nbdFd, NBD_CLEAR_SOCK);
        _exit(0);
    }

    // Parent: close our copies of the fds.
    // The kernel has its own reference to the vsock socket (from fget
    // in NBD_SET_SOCK), and the child has copies of the fds.
    close(nbdFd);
    vsockFd.reset();

    char devPath[32];
    snprintf(devPath, sizeof(devPath), "/dev/nbd%d", nbdIndex);
    LOG_INFO("Block device %s ready", devPath);
    return std::string(devPath);
}
