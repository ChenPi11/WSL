// Copyright (C) Microsoft Corporation. All rights reserved.

#include "precomp.h"
#include "BlockDeviceProxy.h"
#include "disk.hpp"
#include "hvsocket.hpp"
#include "lxinitshared.h"

#pragma comment(lib, "ws2_32.lib")

// NBD protocol uses POSIX errno values
#ifndef EIO
#define EIO 5
#endif
#ifndef EINVAL
#define EINVAL 22
#endif

namespace wsl::windows::common::blockdevice {

namespace {

// NBD protocol magic constants (big-endian)
constexpr uint64_t NBD_MAGIC = 0x956202b8c0e4d6d4;
constexpr uint64_t NBD_CLISERV_MAGIC = 0x49484156454F5054;
constexpr uint32_t NBD_REQUEST_MAGIC = 0x25609513;
constexpr uint32_t NBD_REPLY_MAGIC = 0x67446698;

// NBD command types
constexpr uint16_t NBD_CMD_READ = 0;
constexpr uint16_t NBD_CMD_WRITE = 1;
constexpr uint16_t NBD_CMD_DISC = 2;
constexpr uint16_t NBD_CMD_FLUSH = 4;

// NBD flags for old-style handshake
constexpr uint32_t NBD_FLAG_HAS_FLAGS = (1 << 0);
constexpr uint32_t NBD_FLAG_READ_ONLY = (1 << 1);
constexpr uint32_t NBD_FLAG_SEND_FLUSH = (1 << 2);

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

uint64_t Htonll(uint64_t Value)
{
    // Use Windows byteswap intrinsic
    return _byteswap_uint64(Value);
}

uint64_t Ntohll(uint64_t Value)
{
    return _byteswap_uint64(Value);
}

int SendAll(SOCKET Sock, const void* Data, int Length)
{
    const char* ptr = static_cast<const char*>(Data);
    int remaining = Length;
    while (remaining > 0)
    {
        int sent = send(Sock, ptr, remaining, 0);
        if (sent <= 0)
        {
            return -1;
        }
        ptr += sent;
        remaining -= sent;
    }
    return Length;
}

int RecvAll(SOCKET Sock, void* Data, int Length)
{
    char* ptr = static_cast<char*>(Data);
    int remaining = Length;
    while (remaining > 0)
    {
        int recvd = recv(Sock, ptr, remaining, 0);
        if (recvd <= 0)
        {
            return -1;
        }
        ptr += recvd;
        remaining -= recvd;
    }
    return Length;
}

} // anonymous namespace

void PhysicalBlockDevice::Open(const std::wstring& Path, bool Writable)
{
    Close();

    DWORD access = GENERIC_READ;
    if (Writable)
    {
        access |= GENERIC_WRITE;
    }

    m_handle.reset(CreateFileW(
        Path.c_str(),
        access,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        nullptr));

    THROW_LAST_ERROR_IF(!m_handle);

    QueryDeviceSize();
}

void PhysicalBlockDevice::Close()
{
    if (m_handle)
    {
        m_handle.reset();
    }
    m_deviceSize = 0;
    m_sectorSize = 512;
}

bool PhysicalBlockDevice::Read(uint64_t Offset, void* Buffer, uint32_t Length)
{
    LARGE_INTEGER liOffset;
    liOffset.QuadPart = static_cast<LONGLONG>(Offset);
    OVERLAPPED overlapped = {};
    overlapped.Offset = liOffset.LowPart;
    overlapped.OffsetHigh = liOffset.HighPart;

    DWORD bytesRead = 0;
    return !!ReadFile(m_handle.get(), Buffer, Length, &bytesRead, &overlapped);
}

bool PhysicalBlockDevice::Write(uint64_t Offset, const void* Buffer, uint32_t Length)
{
    LARGE_INTEGER liOffset;
    liOffset.QuadPart = static_cast<LONGLONG>(Offset);
    OVERLAPPED overlapped = {};
    overlapped.Offset = liOffset.LowPart;
    overlapped.OffsetHigh = liOffset.HighPart;

    DWORD bytesWritten = 0;
    return !!WriteFile(m_handle.get(), Buffer, Length, &bytesWritten, &overlapped);
}

bool PhysicalBlockDevice::Flush()
{
    return !!FlushFileBuffers(m_handle.get());
}

void PhysicalBlockDevice::QueryDeviceSize()
{
    DISK_GEOMETRY_EX diskGeometry = {};
    DWORD bytesReturned = 0;
    if (DeviceIoControl(
            m_handle.get(),
            IOCTL_DISK_GET_DRIVE_GEOMETRY_EX,
            nullptr,
            0,
            &diskGeometry,
            sizeof(diskGeometry),
            &bytesReturned,
            nullptr))
    {
        m_deviceSize = diskGeometry.DiskSize.QuadPart;
        m_sectorSize = diskGeometry.Geometry.BytesPerSector;
    }
    else
    {
        PARTITION_INFORMATION_EX partInfo = {};
        if (DeviceIoControl(
                m_handle.get(),
                IOCTL_DISK_GET_PARTITION_INFO_EX,
                nullptr,
                0,
                &partInfo,
                sizeof(partInfo),
                &bytesReturned,
                nullptr))
        {
            m_deviceSize = partInfo.PartitionLength.QuadPart;
            m_sectorSize = partInfo.BytesPerSector > 0 ? partInfo.BytesPerSector : 512;
        }
        else
        {
            LARGE_INTEGER size;
            if (GetFileSizeEx(m_handle.get(), &size))
            {
                m_deviceSize = size.QuadPart;
            }
        }
    }
}

BlockDeviceServer::BlockDeviceServer()
{
}

BlockDeviceServer::~BlockDeviceServer()
{
    Stop();
}

void BlockDeviceServer::Start(const GUID& VmId, const std::wstring& PartitionPath, bool Writable)
{
    if (m_running)
    {
        return;
    }

    m_writable = Writable;
    m_device.Open(PartitionPath, Writable);

    m_running = true;
    m_serverThread = std::thread(&BlockDeviceServer::ServerThread, this, VmId);
}

void BlockDeviceServer::Stop()
{
    m_running = false;

    if (m_listenSocket)
    {
        closesocket(m_listenSocket.get());
        m_listenSocket.reset();
    }

    if (m_serverThread.joinable())
    {
        m_serverThread.join();
    }

    m_device.Close();
}

void BlockDeviceServer::ServerThread(const GUID& VmId)
{
    wsl::windows::common::wslutil::SetThreadDescription(L"BlockDeviceServer");

    try
    {
        m_listenSocket = wsl::windows::common::hvsocket::Listen(VmId, LX_INIT_UTILITY_VM_BLOCK_DEVICE_PORT);
    }
    catch (...)
    {
        LOG_CAUGHT_EXCEPTION();
        m_running = false;
        return;
    }

    while (m_running)
    {
        fd_set readfds;
        FD_ZERO(&readfds);
        FD_SET(m_listenSocket.get(), &readfds);

        struct timeval tv = {1, 0};
        int ret = select(0, &readfds, nullptr, nullptr, &tv);
        if (ret < 0)
        {
            break;
        }
        if (ret == 0)
        {
            continue;
        }

        sockaddr_storage addr;
        socklen_t addrLen = sizeof(addr);
        wil::unique_socket client(accept(m_listenSocket.get(), reinterpret_cast<sockaddr*>(&addr), &addrLen));
        if (!client)
        {
            continue;
        }

        // Send NBD old-style handshake
        uint64_t magicNBD = Htonll(NBD_MAGIC);
        uint64_t magicCliserv = Htonll(NBD_CLISERV_MAGIC);
        uint64_t sizeNBO = Htonll(m_device.GetSize());
        uint32_t flagsNBO = htonl(NBD_FLAG_HAS_FLAGS | NBD_FLAG_SEND_FLUSH | (m_writable ? 0 : NBD_FLAG_READ_ONLY));
        char padding[124] = {};

        if (SendAll(client.get(), &magicNBD, sizeof(magicNBD)) < 0) continue;
        if (SendAll(client.get(), &magicCliserv, sizeof(magicCliserv)) < 0) continue;
        if (SendAll(client.get(), &sizeNBO, sizeof(sizeNBO)) < 0) continue;
        if (SendAll(client.get(), &flagsNBO, sizeof(flagsNBO)) < 0) continue;
        if (SendAll(client.get(), padding, sizeof(padding)) < 0) continue;

        // Handle NBD requests
        while (m_running)
        {
            NBDRequest request;
            if (RecvAll(client.get(), &request, sizeof(request)) < 0)
            {
                break;
            }

            request.Magic = ntohl(request.Magic);
            request.Flags = ntohs(request.Flags);
            request.Type = ntohs(request.Type);
            request.Offset = _byteswap_uint64(request.Offset);
            request.Length = ntohl(request.Length);
            // Handle is NOT converted to host order — it is only echoed back
            // in the reply, and must remain in network byte order.

            if (request.Magic != NBD_REQUEST_MAGIC)
            {
                break;
            }

            NBDReply reply;
            reply.Magic = htonl(NBD_REPLY_MAGIC);
            reply.Error = 0;
            reply.Handle = request.Handle;

            switch (request.Type)
            {
            case NBD_CMD_READ:
            {
                std::vector<char> buffer(request.Length);
                if (!m_device.Read(request.Offset, buffer.data(), request.Length))
                {
                    reply.Error = htonl(EIO);
                    SendAll(client.get(), &reply, sizeof(reply));
                }
                else
                {
                    reply.Error = 0;
                    if (SendAll(client.get(), &reply, sizeof(reply)) < 0) goto nbd_done;
                    if (SendAll(client.get(), buffer.data(), request.Length) < 0) goto nbd_done;
                }
                break;
            }
            case NBD_CMD_WRITE:
            {
                std::vector<char> buffer(request.Length);
                if (RecvAll(client.get(), buffer.data(), request.Length) < 0) goto nbd_done;
                if (!m_device.Write(request.Offset, buffer.data(), request.Length))
                {
                    reply.Error = htonl(EIO);
                }
                if (SendAll(client.get(), &reply, sizeof(reply)) < 0) goto nbd_done;
                break;
            }
            case NBD_CMD_FLUSH:
            {
                if (!m_device.Flush())
                {
                    reply.Error = htonl(EIO);
                }
                if (SendAll(client.get(), &reply, sizeof(reply)) < 0) goto nbd_done;
                break;
            }
            case NBD_CMD_DISC:
                goto nbd_done;
            default:
                reply.Error = htonl(EINVAL);
                if (SendAll(client.get(), &reply, sizeof(reply)) < 0) goto nbd_done;
                break;
            }
        }
nbd_done:;
    }

    m_running = false;
}

} // namespace wsl::windows::common::blockdevice
