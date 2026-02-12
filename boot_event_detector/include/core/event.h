#ifndef BOOT_EVENT_DETECTOR_EVENT_H
#define BOOT_EVENT_DETECTOR_EVENT_H

#include <ida.hpp>
#include <string>
#include <vector>
#include <set>

enum class Tier {
    DEFINITE,
    LIKELY,
    POSSIBLE
};

struct Signal {
    std::string name;
    bool matched;
    bool required;

    Signal(const std::string &n, bool m, bool req = true)
        : name(n), matched(m), required(req) {}
};

enum class EventType {
    GDT_LOAD,
    IDT_LOAD,
    PMODE_ENTER,
    PAGING_ENABLE,
    LONGMODE_ENTER,
    A20_ENABLE,

    BIOS_DISK_READ,
    VIDEO_MODE_SWITCH,
    MEMORY_MAP_QUERY,
    SEGMENT_SETUP,
    STACK_SETUP,
    TLS_GS_SETUP,

    STAGE_DETECT,
    UEFI_BOOT_SERVICE,
    UEFI_PROTOCOL,
    MULTIBOOT_HEADER,
    PE_LOADER,
    UNKNOWN
};

struct BootEvent {
    ea_t address;
    EventType type;
    Tier tier;
    std::string details;
    std::vector<Signal> signals;
    std::vector<ea_t> related;

    int sequence_id;
    bool suppressed;

    BootEvent()
        : address(BADADDR)
        , type(EventType::UNKNOWN)
        , tier(Tier::POSSIBLE)
        , sequence_id(-1)
        , suppressed(false)
    {}

    BootEvent(ea_t addr, EventType t, const std::string &det)
        : address(addr)
        , type(t)
        , tier(Tier::POSSIBLE)
        , details(det)
        , sequence_id(-1)
        , suppressed(false)
    {}

    void add_signal(const std::string &name, bool matched, bool required = true) {
        signals.emplace_back(name, matched, required);
    }

    void compute_tier();

    static const char *type_to_string(EventType t);

    static const char *tier_to_string(Tier t);

    std::string get_signal_summary() const;

    std::string get_comment_text() const;
};

#endif
