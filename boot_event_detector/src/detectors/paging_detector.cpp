#include "detectors/paging_detector.h"
#include <intel.hpp>
#include "core/safe_decode.h"

bool PagingDetector::matches(ea_t ea) {
    insn_t insn;
    if (safe_decode_insn(&insn, ea) <= 0)
        return false;

    if (insn.itype == NN_movsp
        && insn.ops[0].type == o_crreg
        && insn.ops[0].reg == 3)
    {
        return true;
    }
    return false;
}

bool PagingDetector::has_cr0_pg_nearby(ea_t ea, int range) const {
    auto check_cr0 = [](const insn_t &insn, ea_t) -> bool {
        return insn.itype == NN_movsp
            && insn.ops[0].type == o_crreg
            && insn.ops[0].reg == 0;
    };

    if (walk_forward(ea + 3, range * 5, check_cr0))
        return true;
    return walk_backward(ea, range * 5, check_cr0);
}

bool PagingDetector::has_cr4_setup_nearby(ea_t ea, int range) const {
    return walk_backward(ea, range * 5, [](const insn_t &insn, ea_t) -> bool {
        return insn.itype == NN_movsp
            && insn.ops[0].type == o_crreg
            && insn.ops[0].reg == 4;
    });
}

BootEvent *PagingDetector::analyze(ea_t ea) {
    insn_t insn;
    if (safe_decode_insn(&insn, ea) <= 0)
        return nullptr;

    auto *evt = new BootEvent(ea, EventType::PAGING_ENABLE, "");
    evt->add_signal("CR3 write", true);

    bool cr0_pg = has_cr0_pg_nearby(ea);
    evt->add_signal("CR0.PG set", cr0_pg);

    bool cr4 = has_cr4_setup_nearby(ea);
    evt->add_signal("CR4 setup", cr4, false);

    evt->compute_tier();
    return evt;
}
