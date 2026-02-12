#include "detectors/descriptor_detector.h"
#include <intel.hpp>
#include "core/safe_decode.h"

bool DescriptorDetector::matches(ea_t ea) {
    insn_t insn;
    if (safe_decode_insn(&insn, ea) <= 0)
        return false;
    return (insn.itype == NN_lgdt || insn.itype == NN_lidt);
}

BootEvent *DescriptorDetector::analyze(ea_t ea) {
    insn_t insn;
    if (safe_decode_insn(&insn, ea) <= 0)
        return nullptr;

    EventType type = (insn.itype == NN_lgdt)
        ? EventType::GDT_LOAD
        : EventType::IDT_LOAD;

    char addr_buf[32];
    qsnprintf(addr_buf, sizeof(addr_buf), "0x%llX", (unsigned long long)ea);

    std::string details = (type == EventType::GDT_LOAD) ? "lgdt at " : "lidt at ";
    details += addr_buf;

    auto *evt = new BootEvent(ea, type, details);
    evt->add_signal((type == EventType::GDT_LOAD) ? "lgdt instruction" : "lidt instruction", true);
    evt->compute_tier();
    return evt;
}
