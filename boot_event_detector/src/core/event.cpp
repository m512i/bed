#include "core/event.h"

const char *BootEvent::type_to_string(EventType t) {
    switch (t) {
        case EventType::GDT_LOAD:       return "GDT_LOAD";
        case EventType::IDT_LOAD:       return "IDT_LOAD";
        case EventType::PMODE_ENTER:    return "PMODE_ENTER";
        case EventType::PAGING_ENABLE:  return "PAGING_ENABLE";
        case EventType::LONGMODE_ENTER: return "LONGMODE_ENTER";
        case EventType::A20_ENABLE:     return "A20_ENABLE";
        case EventType::BIOS_DISK_READ:    return "BIOS_DISK_READ";
        case EventType::VIDEO_MODE_SWITCH: return "VIDEO_MODE_SWITCH";
        case EventType::MEMORY_MAP_QUERY:  return "MEMORY_MAP_QUERY";
        case EventType::SEGMENT_SETUP:     return "SEGMENT_SETUP";
        case EventType::STACK_SETUP:       return "STACK_SETUP";
        case EventType::TLS_GS_SETUP:     return "TLS_GS_SETUP";
        case EventType::STAGE_DETECT:      return "STAGE_DETECT";
        case EventType::UEFI_BOOT_SERVICE: return "UEFI_BOOT_SVC";
        case EventType::UEFI_PROTOCOL:     return "UEFI_PROTOCOL";
        case EventType::MULTIBOOT_HEADER:  return "MULTIBOOT_HDR";
        case EventType::PE_LOADER:         return "PE_LOADER";
        default:                        return "UNKNOWN";
    }
}

const char *BootEvent::tier_to_string(Tier t) {
    switch (t) {
        case Tier::DEFINITE: return "DEFINITE";
        case Tier::LIKELY:   return "LIKELY";
        case Tier::POSSIBLE: return "POSSIBLE";
        default:             return "UNKNOWN";
    }
}

void BootEvent::compute_tier() {
    int required_total = 0;
    int required_matched = 0;
    int optional_matched = 0;
    int any_matched = 0;

    for (const auto &sig : signals) {
        if (sig.matched)
            any_matched++;
        if (sig.required) {
            required_total++;
            if (sig.matched)
                required_matched++;
        } else {
            if (sig.matched)
                optional_matched++;
        }
    }

    if (required_total == 0) {

        tier = (any_matched >= 2) ? Tier::LIKELY : Tier::POSSIBLE;
        return;
    }

    if (required_matched == required_total) {
        tier = Tier::DEFINITE;
    } else if (required_matched > 0 && (required_matched >= required_total / 2 || optional_matched > 0)) {
        tier = Tier::LIKELY;
    } else {
        tier = Tier::POSSIBLE;
    }
}

std::string BootEvent::get_signal_summary() const {
    std::string summary;
    for (const auto &sig : signals) {
        if (!summary.empty())
            summary += "  ";
        summary += sig.matched ? "\xe2\x9c\x93 " : "\xe2\x9c\x97 ";
        summary += sig.name;
    }
    return summary;
}

std::string BootEvent::get_comment_text() const {
    std::string text = "[BOOT] ";
    text += type_to_string(type);
    text += " -- ";
    text += tier_to_string(tier);
    text += "\n";
    for (const auto &sig : signals) {
        text += "  ";
        text += sig.matched ? "[+] " : "[-] ";
        text += sig.name;
        text += "\n";
    }
    if (!details.empty()) {
        text += "  ";
        text += details;
    }
    return text;
}
