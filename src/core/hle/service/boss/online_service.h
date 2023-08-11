// Copyright 2023 Citra Emulator Project
// Licensed under GPLv2 or any later version
// Refer to the license.txt file included.

#pragma once

#include <string>
#include <variant>
#include <vector>

#include "common/common_types.h"
#include "core/hle/result.h"
#include "core/loader/loader.h"

namespace Kernel {
class MappedBuffer;
}

namespace FileSys {
struct Entry;
class Path;
} // namespace FileSys

namespace Service::BOSS {

constexpr u32 boss_payload_header_length = 0x28;
constexpr u32 boss_magic = Loader::MakeMagic('b', 'o', 's', 's');
constexpr u32 boss_payload_magic = 0x10001;
constexpr u64 news_prog_id = 0x0004013000003502;

constexpr u32 boss_content_header_length = 0x132;
constexpr u32 boss_header_with_hash_length = 0x13C;
constexpr u32 boss_entire_header_length = boss_content_header_length + boss_header_with_hash_length;
constexpr u32 boss_extdata_header_length = 0x18;
constexpr u32 boss_s_entry_size = 0xC00;
constexpr u32 boss_save_header_size = 4;

constexpr u8 task_id_size = 8;
constexpr size_t url_size = 0x200;
constexpr size_t headers_size = 0x360;
constexpr size_t certidlist_size = 3;
constexpr size_t taskidlist_size = 0x400;

constexpr std::array<u8, 8> boss_system_savedata_id{
    0x00, 0x00, 0x00, 0x00, 0x34, 0x00, 0x01, 0x00,
};

#pragma pack(push, 4)
struct BossHeader {
    u8 header_length;
    std::array<u8, 11> zero1;
    u32_be unknown;
    u32_be download_date;
    std::array<u8, 4> zero2;
    u64_be program_id;
    std::array<u8, 4> zero3;
    u32_be datatype;
    u32_be payload_size;
    u32_be ns_data_id;
    u32_be version;
};
#pragma pack(pop)
static_assert(sizeof(BossHeader) == 0x34, "BossHeader has incorrect size");

struct NsDataEntry {
    std::string filename;
    BossHeader header;
};

enum class PropertyID : u16 {
    INTERVAL = 0x03,
    DURATION = 0x04,
    URL = 0x07,
    HEADERS = 0x0D,
    CERTID = 0x0E,
    CERTIDLIST = 0x0F,
    LOADCERT = 0x10,
    LOADROOTCERT = 0x11,
    TOTALTASKS = 0x35,
    TASKIDLIST = 0x36,
};

struct BossSVData {
    INSERT_PADDING_BYTES(0x10);
    u64 program_id;
    std::array<char, task_id_size> task_id;
};

struct BossSSData {
    INSERT_PADDING_BYTES(0x21C);
    std::array<u8, url_size> url;
};

using BossTaskProperty = std::variant<u8, u16, u32, std::vector<u8>, std::vector<u32>>;
struct BossTaskProperties {
    bool task_result;
    std::map<PropertyID, BossTaskProperty> properties{
        {static_cast<PropertyID>(0x00), u8()},
        {static_cast<PropertyID>(0x01), u8()},
        {static_cast<PropertyID>(0x02), u32()},
        {PropertyID::INTERVAL, u32()},
        {PropertyID::DURATION, u32()},
        {static_cast<PropertyID>(0x05), u8()},
        {static_cast<PropertyID>(0x06), u8()},
        {PropertyID::URL, std::vector<u8>(url_size)},
        {static_cast<PropertyID>(0x08), u32()},
        {static_cast<PropertyID>(0x09), u8()},
        {static_cast<PropertyID>(0x0A), std::vector<u8>(0x100)},
        {static_cast<PropertyID>(0x0B), std::vector<u8>(0x200)},
        {static_cast<PropertyID>(0x0C), u32()},
        {PropertyID::HEADERS, std::vector<u8>(headers_size)},
        {PropertyID::CERTID, u32()},
        {PropertyID::CERTIDLIST, std::vector<u32>(certidlist_size)},
        {PropertyID::LOADCERT, u8()},
        {PropertyID::LOADROOTCERT, u8()},
        {static_cast<PropertyID>(0x12), u8()},
        {static_cast<PropertyID>(0x13), u32()},
        {static_cast<PropertyID>(0x14), u32()},
        {static_cast<PropertyID>(0x15), std::vector<u8>(0x40)},
        {static_cast<PropertyID>(0x16), u32()},
        {static_cast<PropertyID>(0x18), u8()},
        {static_cast<PropertyID>(0x19), u8()},
        {static_cast<PropertyID>(0x1A), u8()},
        {static_cast<PropertyID>(0x1B), u32()},
        {static_cast<PropertyID>(0x1C), u32()},
        {PropertyID::TOTALTASKS, u16()},
        {PropertyID::TASKIDLIST, std::vector<u8>(taskidlist_size)},
        {static_cast<PropertyID>(0x3B), u32()},
        {static_cast<PropertyID>(0x3E), std::vector<u8>(0x200)},
        {static_cast<PropertyID>(0x3F), u8()},
    };
};

class OnlineService final {
public:
    explicit OnlineService(Core::System& system_);

    ResultCode InitializeSession(u64 init_program_id);
    void RegisterTask(const u32 size, Kernel::MappedBuffer& buffer);
    ResultCode UnregisterTask(const u32 size, Kernel::MappedBuffer& buffer);
    void GetTaskIdList();
    u16 GetNsDataIdList(const u32 filter, const u32 max_entries, Kernel::MappedBuffer& buffer);
    ResultCode SendProperty(const u16 id, const u32 size, Kernel::MappedBuffer& buffer);
    ResultCode ReceiveProperty(const u16 id, const u32 size, Kernel::MappedBuffer& buffer);

private:
    std::vector<FileSys::Entry> GetBossExtDataFiles();
    FileSys::Path GetBossDataDir();
    std::vector<NsDataEntry> GetNsDataEntries();

    BossTaskProperties current_props;
    std::map<std::string, BossTaskProperties> task_id_list;

    Core::System& system;
    u64 program_id;
    u64 extdata_id;
};

} // namespace Service::BOSS
