// Copyright (C) Microsoft Corporation. All rights reserved.

#pragma once

#include <string>

//
// Set up an NBD block device by connecting to a vsock NBD server.
// Returns the device path (e.g., "/dev/nbd0") on success, or empty string on failure.
//
std::string SetupBlockDevice(unsigned int VsockPort);
