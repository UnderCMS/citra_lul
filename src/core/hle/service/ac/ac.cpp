// Copyright 2016 Citra Emulator Project
// Licensed under GPLv2 or any later version
// Refer to the license.txt file included.

#include <vector>
#include "common/archives.h"
#include "common/common_types.h"
#include "common/logging/log.h"
#include "common/settings.h"
#include "core/core.h"
#include "core/hle/ipc.h"
#include "core/hle/ipc_helpers.h"
#include "core/hle/kernel/event.h"
#include "core/hle/kernel/handle_table.h"
#include "core/hle/kernel/shared_page.h"
#include "core/hle/result.h"
#include "core/hle/service/ac/ac.h"
#include "core/hle/service/ac/ac_i.h"
#include "core/hle/service/ac/ac_u.h"
#include "core/hle/service/soc/soc_u.h"
#include "core/memory.h"

namespace Service::AC {
void Module::Interface::CreateDefaultConfig(Kernel::HLERequestContext& ctx) {
    IPC::RequestParser rp(ctx);

    std::vector<u8> buffer(sizeof(ACConfig));
    std::memcpy(buffer.data(), &ac->default_config, buffer.size());

    IPC::RequestBuilder rb = rp.MakeBuilder(1, 2);
    rb.Push(RESULT_SUCCESS);
    rb.PushStaticBuffer(std::move(buffer), 0);

    LOG_WARNING(Service_AC, "(STUBBED) called");
}

void Module::Interface::ConnectAsync(Kernel::HLERequestContext& ctx) {
    IPC::RequestParser rp(ctx);

    const u32 pid = rp.PopPID();
    ac->connect_event = rp.PopObject<Kernel::Event>();
    rp.Skip(2, false); // Buffer descriptor

    ac->Connect(pid);

    IPC::RequestBuilder rb = rp.MakeBuilder(1, 0);
    rb.Push(RESULT_SUCCESS);

    LOG_WARNING(Service_AC, "(STUBBED) called, pid={}", pid);
}

void Module::Interface::GetConnectResult(Kernel::HLERequestContext& ctx) {
    IPC::RequestParser rp(ctx);
    [[maybe_unused]] const u32 pid = rp.PopPID();

    IPC::RequestBuilder rb = rp.MakeBuilder(1, 0);
    rb.Push(ac->connect_result);
}

void Module::Interface::CancelConnectAsync(Kernel::HLERequestContext& ctx) {
    IPC::RequestParser rp(ctx);
    const u32 pid = rp.PopPID();

    IPC::RequestBuilder rb = rp.MakeBuilder(1, 0);
    rb.Push(RESULT_SUCCESS);

    LOG_WARNING(Service_AC, "(STUBBED) called, pid={}", pid);
}

void Module::Interface::CloseAsync(Kernel::HLERequestContext& ctx) {
    IPC::RequestParser rp(ctx);
    const u32 pid = rp.PopPID();

    ac->close_event = rp.PopObject<Kernel::Event>();

    ac->Disconnect(pid);

    IPC::RequestBuilder rb = rp.MakeBuilder(1, 0);
    rb.Push(RESULT_SUCCESS);

    LOG_WARNING(Service_AC, "(STUBBED) called, pid={}", pid);
}

void Module::Interface::GetCloseResult(Kernel::HLERequestContext& ctx) {
    IPC::RequestParser rp(ctx);
    [[maybe_unused]] const u32 pid = rp.PopPID();

    IPC::RequestBuilder rb = rp.MakeBuilder(1, 0);
    rb.Push(ac->close_result);
}

void Module::Interface::GetWifiStatus(Kernel::HLERequestContext& ctx) {
    IPC::RequestParser rp(ctx);

    if (!ac->ac_connected) {
        IPC::RequestBuilder rb = rp.MakeBuilder(1, 0);
        rb.Push(ERROR_NOT_CONNECTED);
        return;
    }

    IPC::RequestBuilder rb = rp.MakeBuilder(2, 0);
    rb.Push(RESULT_SUCCESS);
    rb.Push<u32>(static_cast<u32>(WifiStatus::STATUS_CONNECTED_SLOT1));

    LOG_WARNING(Service_AC, "(STUBBED) called");
}

void Module::Interface::GetCurrentAPInfo(Kernel::HLERequestContext& ctx) {
    IPC::RequestParser rp(ctx);
    const u32 len = rp.Pop<u32>();
    const u32 pid = rp.PopPID();

    if (!ac->ac_connected) {
        IPC::RequestBuilder rb = rp.MakeBuilder(1, 0);
        rb.Push(ERROR_NOT_CONNECTED);
        return;
    }

    constexpr const char* citra_ap = "Citra_AP";
    constexpr s16 good_signal_strength = -40; // Decibels
    constexpr u8 unknown1_value = 5;

    SharedPage::Handler& shared_page = ac->kernel.GetSharedPageHandler();
    SharedPage::MacAddress mac = shared_page.GetMacAddress();

    APInfo info{};
    std::strcpy(info.ssid.data(), citra_ap);
    info.ssid_len = static_cast<u32>(std::strlen(citra_ap));
    info.bssid = mac;
    info.signal_strength = good_signal_strength;
    info.link_level = static_cast<u16>(shared_page.GetWifiLinkLevel());
    info.unknown1 = unknown1_value;

    std::vector<u8> out_info(len);
    std::memcpy(out_info.data(), &info, std::min(len, static_cast<u32>(sizeof(info))));

    IPC::RequestBuilder rb = rp.MakeBuilder(1, 2);
    rb.Push(RESULT_SUCCESS);
    rb.PushStaticBuffer(out_info, 0);

    LOG_WARNING(Service_AC, "(STUBBED) called, pid={}", pid);
}

void Module::Interface::GetConnectingInfraPriority(Kernel::HLERequestContext& ctx) {
    IPC::RequestParser rp(ctx);

    if (!ac->ac_connected) {
        IPC::RequestBuilder rb = rp.MakeBuilder(1, 0);
        rb.Push(ERROR_NOT_CONNECTED);
        return;
    }

    IPC::RequestBuilder rb = rp.MakeBuilder(2, 0);
    rb.Push(RESULT_SUCCESS);
    rb.Push<u32>(static_cast<u32>(InfraPriority::PRIORITY_HIGH));

    LOG_WARNING(Service_AC, "(STUBBED) called");
}

void Module::Interface::GetStatus(Kernel::HLERequestContext& ctx) {
    IPC::RequestParser rp(ctx);

    IPC::RequestBuilder rb = rp.MakeBuilder(2, 0);
    rb.Push(RESULT_SUCCESS);
    rb.Push<u32>(static_cast<u32>(ac->ac_connected ? NetworkStatus::STATUS_INTERNET
                                                   : NetworkStatus::STATUS_DISCONNECTED));

    LOG_WARNING(Service_AC, "(STUBBED) called");
}

void Module::Interface::GetInfraPriority(Kernel::HLERequestContext& ctx) {
    IPC::RequestParser rp(ctx);
    [[maybe_unused]] const std::vector<u8>& ac_config = rp.PopStaticBuffer();

    IPC::RequestBuilder rb = rp.MakeBuilder(2, 0);
    rb.Push(RESULT_SUCCESS);
    rb.Push<u32>(static_cast<u32>(InfraPriority::PRIORITY_HIGH));

    LOG_WARNING(Service_AC, "(STUBBED) called");
}

void Module::Interface::SetFromApplication(Kernel::HLERequestContext& ctx) {
    IPC::RequestParser rp(ctx);
    const u32 unknown = rp.Pop<u32>();
    auto config = rp.PopStaticBuffer();

    IPC::RequestBuilder rb = rp.MakeBuilder(1, 2);
    rb.Push(RESULT_SUCCESS);
    rb.PushStaticBuffer(config, 0);

    LOG_WARNING(Service_AC, "(STUBBED) called, unknown={}", unknown);
}

void Module::Interface::SetRequestEulaVersion(Kernel::HLERequestContext& ctx) {
    IPC::RequestParser rp(ctx);

    const u32 major = rp.Pop<u8>();
    const u32 minor = rp.Pop<u8>();

    const std::vector<u8>& ac_config = rp.PopStaticBuffer();

    // TODO(Subv): Copy over the input ACConfig to the stored ACConfig.

    IPC::RequestBuilder rb = rp.MakeBuilder(1, 2);
    rb.Push(RESULT_SUCCESS);
    rb.PushStaticBuffer(std::move(ac_config), 0);

    LOG_WARNING(Service_AC, "(STUBBED) called, major={}, minor={}", major, minor);
}

void Module::Interface::GetNZoneBeaconNotFoundEvent(Kernel::HLERequestContext& ctx) {
    IPC::RequestParser rp(ctx);
    rp.PopPID();
    auto event = rp.PopObject<Kernel::Event>();

    event->Signal();

    IPC::RequestBuilder rb = rp.MakeBuilder(1, 0);
    rb.Push(RESULT_SUCCESS);

    LOG_WARNING(Service_AC, "(STUBBED) called");
}

void Module::Interface::RegisterDisconnectEvent(Kernel::HLERequestContext& ctx) {
    IPC::RequestParser rp(ctx);
    rp.Skip(2, false); // ProcessId descriptor

    ac->disconnect_event = rp.PopObject<Kernel::Event>();
    if (ac->disconnect_event) {
        ac->disconnect_event->SetName("AC:disconnect_event");
    }

    IPC::RequestBuilder rb = rp.MakeBuilder(1, 0);
    rb.Push(RESULT_SUCCESS);

    LOG_WARNING(Service_AC, "(STUBBED) called");
}

void Module::Interface::GetConnectingProxyEnable(Kernel::HLERequestContext& ctx) {
    IPC::RequestParser rp(ctx);
    constexpr bool proxy_enabled = false;

    IPC::RequestBuilder rb = rp.MakeBuilder(2, 0);
    rb.Push(RESULT_SUCCESS);
    rb.Push(proxy_enabled);

    LOG_WARNING(Service_AC, "(STUBBED) called");
}

void Module::Interface::IsConnected(Kernel::HLERequestContext& ctx) {
    IPC::RequestParser rp(ctx);
    const u32 unk = rp.Pop<u32>();
    const u32 pid = rp.PopPID();

    IPC::RequestBuilder rb = rp.MakeBuilder(2, 0);
    rb.Push(RESULT_SUCCESS);
    rb.Push(ac->ac_connected);

    LOG_DEBUG(Service_AC, "(STUBBED) called unk=0x{:08X} pid={}", unk, pid);
}

void Module::Interface::SetClientVersion(Kernel::HLERequestContext& ctx) {
    IPC::RequestParser rp(ctx);

    const u32 version = rp.Pop<u32>();
    rp.PopPID();

    LOG_DEBUG(Service_AC, "(STUBBED) called, version: 0x{:08X}", version);

    IPC::RequestBuilder rb = rp.MakeBuilder(1, 0);
    rb.Push(RESULT_SUCCESS);
}

u32 Module::Interface::ConnectFromHLE() {
    u32 new_fake_pid = ++ac->current_fake_pid;
    ac->Connect(new_fake_pid);
    return new_fake_pid;
}

void Module::Interface::DisconnectFromHLE(u32 fake_pid) {
    ac->Disconnect(fake_pid);
}

void Module::Connect(u32 pid) {
    if (connect_event) {
        connect_event->SetName("AC:connect_event");
        connect_event->Signal();
    }

    if (connected_pids.size() == 0) {
        // TODO(PabloMK7) Publish to subscriber 0x300

        ac_connected = true;

        // TODO(PabloMK7) Move shared page modification to NWM once it is implemented.
        SharedPage::Handler& shared_page = kernel.GetSharedPageHandler();
        const bool can_access_internet = CanAccessInternet();
        if (can_access_internet) {
            shared_page.SetWifiState(SharedPage::WifiState::INTERNET);
            shared_page.SetWifiLinkLevel(SharedPage::WifiLinkLevel::BEST);
        } else {
            shared_page.SetWifiState(SharedPage::WifiState::ENABLED);
            shared_page.SetWifiLinkLevel(SharedPage::WifiLinkLevel::OFF);
        }
    }

    if (connected_pids.find(pid) == connected_pids.end()) {
        connected_pids.insert(pid);
        connect_result = RESULT_SUCCESS;
    } else {
        connect_result = ERROR_ALREADY_CONNECTED;
    }
}

void Module::Disconnect(u32 pid) {

    if (close_event) {
        close_event->SetName("AC:close_event");
        close_event->Signal();
    }

    if (connected_pids.find(pid) != connected_pids.end()) {
        connected_pids.erase(pid);
        close_result = RESULT_SUCCESS;
    } else {
        close_result = ERROR_NOT_CONNECTED;
    }

    if (connected_pids.size() == 0) {
        ac_connected = false;
        if (disconnect_event) {
            disconnect_event->Signal();
        }

        // TODO(PabloMK7) Move shared page modification to NWM once it is implemented.
        SharedPage::Handler& shared_page = kernel.GetSharedPageHandler();
        shared_page.SetWifiState(SharedPage::WifiState::ENABLED);
        shared_page.SetWifiLinkLevel(SharedPage::WifiLinkLevel::OFF);
    }
}

bool Module::CanAccessInternet() {
    std::shared_ptr<SOC::SOC_U> socu_module = SOC::GetService(Core::System::GetInstance());
    if (socu_module) {
        return socu_module->GetDefaultInterfaceInfo().has_value();
    }
    return false;
}

Module::Module(Kernel::KernelSystem& kernel) : kernel(kernel) {}

Module::Interface::Interface(std::shared_ptr<Module> ac, const char* name, u32 max_session)
    : ServiceFramework(name, max_session), ac(std::move(ac)) {}

void InstallInterfaces(Core::System& system) {
    auto& service_manager = system.ServiceManager();
    auto ac = std::make_shared<Module>(system.Kernel());
    std::make_shared<AC_I>(ac)->InstallAsService(service_manager);
    std::make_shared<AC_U>(ac)->InstallAsService(service_manager);
}

std::shared_ptr<AC_U> GetService(Core::System& system) {
    return system.ServiceManager().GetService<AC_U>("ac:u");
}

template <class Archive>
void Module::serialize(Archive& ar, const unsigned int) {
    ar& ac_connected;
    ar& close_event;
    ar& connect_event;
    ar& disconnect_event;
    u32 connect_result_32 = connect_result.raw;
    ar& connect_result_32;
    connect_result.raw = connect_result_32;
    u32 close_result_32 = close_result.raw;
    ar& close_result_32;
    close_result.raw = close_result_32;
    ar& connected_pids;
    // default_config is never written to
}

} // namespace Service::AC

SERIALIZE_IMPL(Service::AC::Module)
