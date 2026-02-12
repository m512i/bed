#include "detectors/uefi_boot_service_detector.h"
#include <bytes.hpp>
#include <name.hpp>
#include <funcs.hpp>
#include <intel.hpp>
#include "core/safe_decode.h"

const UefiBootServiceDetector::EfiFuncInfo UefiBootServiceDetector::boot_services_[] = {
    { 0x18,  "RaiseTPL",             false },
    { 0x20,  "RestoreTPL",           false },
    { 0x28,  "AllocatePages",        false },
    { 0x30,  "FreePages",            false },
    { 0x38,  "GetMemoryMap",         true  },
    { 0x40,  "AllocatePool",         false },
    { 0x48,  "FreePool",             false },
    { 0x50,  "CreateEvent",          false },
    { 0x58,  "SetTimer",             false },
    { 0x60,  "WaitForEvent",         false },
    { 0x68,  "SignalEvent",          false },
    { 0x70,  "CloseEvent",           false },
    { 0x78,  "CheckEvent",           false },
    { 0x80,  "InstallProtocolInterface",  false },
    { 0x88,  "ReinstallProtocolInterface", false },
    { 0x90,  "UninstallProtocolInterface", false },
    { 0x98,  "HandleProtocol",       false },
    { 0xA8,  "RegisterProtocolNotify", false },
    { 0xB0,  "LocateHandle",         false },
    { 0xB8,  "LocateDevicePath",     false },
    { 0xC0,  "InstallConfigurationTable", false },
    { 0xC8,  "LoadImage",            true  },
    { 0xD0,  "StartImage",           true  },
    { 0xD8,  "Exit",                 false },
    { 0xE0,  "UnloadImage",          false },
    { 0xE8,  "ExitBootServices",     true  },
    { 0xF0,  "GetNextMonotonicCount", false },
    { 0xF8,  "Stall",                false },
    { 0x100, "SetWatchdogTimer",     false },
    { 0x110, "OpenProtocol",         false },
    { 0x118, "CloseProtocol",        false },
    { 0x120, "OpenProtocolInformation", false },
    { 0x128, "ProtocolsPerHandle",   false },
    { 0x130, "LocateHandleBuffer",   false },
    { 0x138, "LocateProtocol",       false },
    { 0x140, "InstallMultipleProtocolInterfaces", false },
    { 0x148, "UninstallMultipleProtocolInterfaces", false },
    { 0, nullptr, false }
};

const UefiBootServiceDetector::EfiFuncInfo *UefiBootServiceDetector::match_boot_service(ea_t ea) const {
    insn_t insn;
    if (safe_decode_insn(&insn, ea) <= 0)
        return nullptr;

    if (insn.itype == NN_callni || insn.itype == NN_call) {
        if (insn.ops[0].type == o_displ) {
            uint32 off = (uint32)insn.ops[0].addr;
            for (int i = 0; boot_services_[i].name; i++) {
                if (boot_services_[i].offset == off)
                    return &boot_services_[i];
            }
        }
    }

    qstring func_name;
    if (get_name(&func_name, ea) > 0 || get_name(&func_name, ea, GN_DEMANGLED) > 0) {
        for (int i = 0; boot_services_[i].name; i++) {
            if (func_name.find(boot_services_[i].name) != qstring::npos)
                return &boot_services_[i];
        }
    }

    return nullptr;
}

bool UefiBootServiceDetector::matches(ea_t ea) {
    return match_boot_service(ea) != nullptr;
}

BootEvent *UefiBootServiceDetector::analyze(ea_t ea) {
    const EfiFuncInfo *info = match_boot_service(ea);
    if (!info)
        return nullptr;

    auto *evt = new BootEvent(ea, EventType::UEFI_BOOT_SERVICE, "");

    evt->add_signal("EFI_BOOT_SERVICES call", true);

    char off_buf[64];
    qsnprintf(off_buf, sizeof(off_buf), "offset 0x%X (%s)", info->offset, info->name);
    evt->add_signal(off_buf, true, info->critical);

    evt->add_signal("boot-critical function", info->critical, false);

    qstring func_name;
    func_t *fn = get_func(ea);
    if (fn && get_func_name(&func_name, fn->start_ea) > 0) {
        char ctx_buf[256];
        qsnprintf(ctx_buf, sizeof(ctx_buf), "inside IDA function %s", func_name.c_str());
        evt->add_signal(ctx_buf, true, false);
        evt->details = info->name;
        char detail_buf[128];
        qsnprintf(detail_buf, sizeof(detail_buf), " (BS+0x%X)", info->offset);
        evt->details += detail_buf;
        if (info->critical)
            evt->details += " [CRITICAL]";
        evt->details += " in ";
        evt->details += func_name.c_str();
    } else {
        evt->details = info->name;
        char detail_buf[128];
        qsnprintf(detail_buf, sizeof(detail_buf), " (BS+0x%X)", info->offset);
        evt->details += detail_buf;
        if (info->critical)
            evt->details += " [CRITICAL]";
    }

    evt->compute_tier();
    return evt;
}
