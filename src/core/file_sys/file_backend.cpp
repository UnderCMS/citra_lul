// Copyright 2015 Citra Emulator Project
// Licensed under GPLv2 or any later version
// Refer to the license.txt file included.

#include "file_backend.h"

namespace FileSys {
bool FileBackend::AllowsCachedReads() const {
    return false;
}
bool FileBackend::CacheReady(std::size_t file_offset, std::size_t length) {
    return false;
}
} // namespace FileSys