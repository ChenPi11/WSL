// Copyright (C) Microsoft Corporation. All rights reserved.

#pragma once

#include <wil/resource.h>
#include <string>
#include <thread>
#include <atomic>

namespace wsl::windows::common::blockdevice {

//
// Manages a block device backed by a physical partition or disk.
// Opens \\.\HarddiskXPartitionY with FILE_SHARE_READ|FILE_SHARE_WRITE
// to allow concurrent access without taking the disk offline.
//
class PhysicalBlockDevice
{
public:
    PhysicalBlockDevice() = default;
    ~PhysicalBlockDevice() = default;

    PhysicalBlockDevice(const PhysicalBlockDevice&) = delete;
    PhysicalBlockDevice& operator=(const PhysicalBlockDevice&) = delete;

    void Open(const std::wstring& Path, bool Writable);
    void Close();

    bool Read(uint64_t Offset, void* Buffer, uint32_t Length);
    bool Write(uint64_t Offset, const void* Buffer, uint32_t Length);
    bool Flush();

    uint64_t GetSize() const { return m_deviceSize; }
    uint32_t GetSectorSize() const { return m_sectorSize; }
    bool IsOpen() const { return m_handle.is_valid(); }

private:
    void QueryDeviceSize();

    wil::unique_hfile m_handle;
    uint64_t m_deviceSize = 0;
    uint32_t m_sectorSize = 512;
};

//
// NBD protocol server over vsock.
// Exposes a Windows partition to WSL2 Linux as an NBD block device.
// The Linux nbd-client (or kernel NBD module) connects here and gets
// a block device (/dev/nbdX) that can be mounted directly.
//
class BlockDeviceServer
{
public:
    BlockDeviceServer();
    ~BlockDeviceServer();

    BlockDeviceServer(const BlockDeviceServer&) = delete;
    BlockDeviceServer& operator=(const BlockDeviceServer&) = delete;

    void Start(const GUID& VmId, const std::wstring& PartitionPath, bool Writable);
    void Stop();
    bool IsRunning() const { return m_running; }

private:
    void ServerThread(const GUID& VmId);

    PhysicalBlockDevice m_device;
    std::atomic<bool> m_running{false};
    bool m_writable = false;
    std::thread m_serverThread;
    wil::unique_socket m_listenSocket;
};

} // namespace wsl::windows::common::blockdevice
