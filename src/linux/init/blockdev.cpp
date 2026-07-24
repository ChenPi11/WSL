// Copyright (C) Microsoft Corporation. All rights reserved.

#include "blockdev.h"
#include "util.h"
#include "common.h"

#include <linux/nbd.h>
#include <sys/ioctl.h>
#include <sys/stat.h>

#include <fcntl.h>
#include <unistd.h>
#include <cstring>
#include <cstdio>
#include <cstdint>
#include <arpa/inet.h>

// Network-to-host for 64-bit values (x86 is LE, NBD is big-endian)
static inline uint64_t Ntohll(uint64_t x) { return __builtin_bswap64(x); }

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
    wil::unique_fd vsockFd = UtilConnectVsock(VsockPort, true);
    if (!vsockFd)
    {
        LOG_ERROR("Failed to connect to vsock port %u", VsockPort);
        return {};
    }

    // Read the NBD old-style handshake from the vsock connection.
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

    // Pass the vsock socket directly to the kernel NBD module.
    // NBD_SET_SOCK calls sockfd_lookup(fd) which accepts any socket
    // type, including AF_VSOCK.
    if (ioctl(nbdFd, NBD_SET_SOCK, vsockFd.get()) < 0)
    {
        LOG_ERROR("NBD_SET_SOCK failed: %s", strerror(errno));
        close(nbdFd);
        return {};
    }

    // Fork: child blocks on NBD_DO_IT, parent returns device path.
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
        // Child: blocks until NBD connection terminates
        ioctl(nbdFd, NBD_DO_IT);
        ioctl(nbdFd, NBD_CLEAR_SOCK);
        close(nbdFd);
        _exit(0);
    }

    // Parent: close our copies, return the device path.
    close(nbdFd);
    vsockFd.reset();

    char devPath[32];
    snprintf(devPath, sizeof(devPath), "/dev/nbd%d", nbdIndex);
    LOG_INFO("Block device %s ready", devPath);
    return std::string(devPath);
}
