#include "analysis/mode_tracker.h"
#include "core/safe_decode.h"
#include <ida.hpp>
#include <bytes.hpp>
#include <intel.hpp>
#include <kernwin.hpp>

ModeTracker::ModeTracker() {}

void ModeTracker::record_snapshot(ea_t ea, CpuMode prev, const std::string &trigger) {
    StateSnapshot snap;
    snap.address = ea;
    snap.state = state_;
    snap.prev_mode = prev;
    snap.new_mode = state_.mode;
    snap.trigger = trigger;
    snapshots_.push_back(snap);
}

uint64 ModeTracker::resolve_reg_value(ea_t ea, int reg, int max_back) const {
    uint64 result = 0;
    bool found = false;

    walk_backward(ea, max_back, [&](const insn_t &insn, ea_t) -> bool {
        if (insn.itype == NN_mov
            && insn.ops[0].type == o_reg
            && insn.ops[0].reg == reg
            && insn.ops[1].type == o_imm)
        {
            result = insn.ops[1].value;
            found = true;
            return true;
        }
        if (insn.ops[0].type == o_reg && insn.ops[0].reg == reg)
            return true;
        return false;
    });

    if (!found) {
        ea_t limit = (ea > (ea_t)max_back) ? (ea - max_back) : 0;
        for (ea_t cur = ea - 1; cur >= limit && cur != BADADDR; cur--) {
            if (!is_loaded(cur))
                continue;
            uint8 b = get_byte(cur);
            if (b >= 0xB8 && b <= 0xBF && is_loaded(cur + 4)) {
                int mov_reg = b - 0xB8;
                if (mov_reg == reg) {
                    result = get_dword(cur + 1);
                    found = true;
                    break;
                }
            }
        }
    }

    return result;
}

void ModeTracker::process_cr0_write(ea_t ea) {
    insn_t insn;
    if (safe_decode_insn(&insn, ea) <= 0)
        return;

    CpuMode prev = state_.mode;
    int src_reg = insn.ops[1].reg;

    bool found_or = false;
    uint64 or_val = 0;
    walk_backward(ea, 30, [&](const insn_t &prev_insn, ea_t) -> bool {
        if (prev_insn.itype == NN_or
            && prev_insn.ops[0].type == o_reg
            && prev_insn.ops[0].reg == src_reg
            && prev_insn.ops[1].type == o_imm)
        {
            or_val = prev_insn.ops[1].value;
            found_or = true;
            return true;
        }
        if (prev_insn.itype == NN_mov
            && prev_insn.ops[0].type == o_reg
            && prev_insn.ops[0].reg == src_reg
            && prev_insn.ops[1].type == o_imm)
        {
            state_.cr0.apply(prev_insn.ops[1].value);
            state_.update_mode(ea);
            if (state_.mode != prev)
                record_snapshot(ea, prev, "mov cr0 (direct)");
            return true;
        }
        return false;
    });

    if (found_or) {
        state_.cr0.apply_or(or_val);
        state_.update_mode(ea);
        if (state_.mode != prev)
            record_snapshot(ea, prev, "or+mov cr0");
    }
}

void ModeTracker::process_cr3_write(ea_t ea) {
    insn_t insn;
    if (safe_decode_insn(&insn, ea) <= 0)
        return;

    int src_reg = insn.ops[1].reg;
    uint64 val = resolve_reg_value(ea, src_reg);
    if (val != 0)
        state_.cr3 = val;
}

void ModeTracker::process_cr4_write(ea_t ea) {
    insn_t insn;
    if (safe_decode_insn(&insn, ea) <= 0)
        return;

    int src_reg = insn.ops[1].reg;

    bool found_or = false;
    uint64 or_val = 0;
    walk_backward(ea, 30, [&](const insn_t &prev_insn, ea_t) -> bool {
        if (prev_insn.itype == NN_or
            && prev_insn.ops[0].type == o_reg
            && prev_insn.ops[0].reg == src_reg
            && prev_insn.ops[1].type == o_imm)
        {
            or_val = prev_insn.ops[1].value;
            found_or = true;
            return true;
        }
        if (prev_insn.itype == NN_mov
            && prev_insn.ops[0].type == o_reg
            && prev_insn.ops[0].reg == src_reg
            && prev_insn.ops[1].type == o_imm)
        {
            state_.cr4.apply(prev_insn.ops[1].value);
            return true;
        }
        return false;
    });

    if (found_or)
        state_.cr4.apply_or(or_val);
}

void ModeTracker::process_efer_write(ea_t ea) {
    CpuMode prev = state_.mode;

    bool found_or = false;
    uint64 or_val = 0;
    walk_backward(ea, 30, [&](const insn_t &insn, ea_t) -> bool {
        if (insn.itype == NN_or
            && insn.ops[0].type == o_reg
            && insn.ops[0].reg == R_ax
            && insn.ops[1].type == o_imm)
        {
            or_val = insn.ops[1].value;
            found_or = true;
            return true;
        }
        if (insn.itype == NN_mov
            && insn.ops[0].type == o_reg
            && insn.ops[0].reg == R_ax
            && insn.ops[1].type == o_imm)
        {
            state_.efer.apply(insn.ops[1].value);
            state_.update_mode(ea);
            if (state_.mode != prev)
                record_snapshot(ea, prev, "wrmsr EFER (direct)");
            return true;
        }
        return false;
    });

    if (found_or) {
        state_.efer.apply_or(or_val);
        state_.update_mode(ea);
        if (state_.mode != prev)
            record_snapshot(ea, prev, "wrmsr EFER (or)");
    }
}

void ModeTracker::scan_nearby_cr_writes(ea_t ea, int range) {
    std::set<ea_t> processed;

    walk_backward(ea, range, [&](const insn_t &insn, ea_t addr) -> bool {
        if (insn.itype == NN_movsp && insn.ops[0].type == o_crreg) {
            if (!processed.count(addr)) {
                processed.insert(addr);
                if (insn.ops[0].reg == 0)
                    process_cr0_write(addr);
                else if (insn.ops[0].reg == 3)
                    process_cr3_write(addr);
                else if (insn.ops[0].reg == 4)
                    process_cr4_write(addr);
            }
        }
        if (insn.itype == NN_wrmsr || (insn.itype == NN_mov && insn.ops[0].type == o_reg))
            ;
        return false;
    });

    walk_forward(ea, range, [&](const insn_t &insn, ea_t addr) -> bool {
        if (insn.itype == NN_movsp && insn.ops[0].type == o_crreg) {
            if (!processed.count(addr)) {
                processed.insert(addr);
                if (insn.ops[0].reg == 0)
                    process_cr0_write(addr);
                else if (insn.ops[0].reg == 3)
                    process_cr3_write(addr);
                else if (insn.ops[0].reg == 4)
                    process_cr4_write(addr);
            }
        }
        return false;
    });
}

void ModeTracker::run(const std::vector<BootEvent *> &events) {
    state_ = CpuState();
    snapshots_.clear();

    std::vector<const BootEvent *> sorted;
    for (auto *evt : events) {
        if (!evt->suppressed)
            sorted.push_back(evt);
    }
    std::sort(sorted.begin(), sorted.end(),
        [](const BootEvent *a, const BootEvent *b) { return a->address < b->address; });

    for (auto *evt : sorted) {
        if (evt->type == EventType::PAGING_ENABLE
            || evt->type == EventType::LONGMODE_ENTER
            || evt->type == EventType::PMODE_ENTER)
        {
            scan_nearby_cr_writes(evt->address, 60);
        }

        switch (evt->type) {
            case EventType::PMODE_ENTER:
                process_cr0_write(evt->address);
                break;
            case EventType::PAGING_ENABLE:
                process_cr3_write(evt->address);
                process_cr0_write(evt->address);
                break;
            case EventType::LONGMODE_ENTER:
                process_efer_write(evt->address);
                break;
            default:
                break;
        }

        insn_t insn;
        if (safe_decode_insn(&insn, evt->address) > 0) {
            if (insn.itype == NN_movsp && insn.ops[0].type == o_crreg) {
                if (insn.ops[0].reg == 4)
                    process_cr4_write(evt->address);
            }
        }
    }

    if (!snapshots_.empty()) {
        msg("[BootEventDetector] ModeTracker: %d mode transitions detected\n",
            (int)snapshots_.size());
        for (const auto &snap : snapshots_) {
            msg("[BootEventDetector]   0x%llX: %s -> %s (%s)\n",
                (unsigned long long)snap.address,
                CpuState::mode_to_string(snap.prev_mode),
                CpuState::mode_to_string(snap.new_mode),
                snap.trigger.c_str());
        }
    }
    msg("[BootEventDetector] ModeTracker final: %s\n", state_.summary().c_str());
}

void ModeTracker::validate_paging_sequence(std::vector<BootEvent *> &events) const {
    bool has_cr3 = false;
    bool has_cr4_pae = false;
    bool has_efer_lme = false;
    bool has_cr0_pg = false;

    for (const auto &snap : snapshots_) {
        if (snap.state.cr3 != 0)
            has_cr3 = true;
        if (snap.state.cr4.PAE)
            has_cr4_pae = true;
        if (snap.state.efer.LME)
            has_efer_lme = true;
        if (snap.state.cr0.PG)
            has_cr0_pg = true;
    }

    for (auto *evt : events) {
        if (evt->suppressed)
            continue;
        if (evt->type != EventType::PAGING_ENABLE)
            continue;

        std::string chain;
        bool valid = true;

        if (!has_cr3) {
            chain += " MISSING:CR3";
            valid = false;
        } else {
            chain += " CR3=OK";
        }

        if (state_.efer.LME || has_efer_lme) {
            if (!has_cr4_pae) {
                chain += " MISSING:CR4.PAE";
                valid = false;
            } else {
                chain += " CR4.PAE=OK";
            }
            if (!has_efer_lme) {
                chain += " MISSING:EFER.LME";
                valid = false;
            } else {
                chain += " EFER.LME=OK";
            }
        }

        if (!has_cr0_pg) {
            chain += " MISSING:CR0.PG";
            valid = false;
        } else {
            chain += " CR0.PG=OK";
        }

        char buf[256];
        qsnprintf(buf, sizeof(buf), " [paging-chain:%s%s]",
            valid ? "VALID" : "INCOMPLETE", chain.c_str());
        evt->details += buf;

        if (valid) {
            evt->add_signal("paging sequence validated", true, false);
            evt->compute_tier();
        }
    }

    if (has_cr0_pg) {
        bool is_longmode = has_cr4_pae && has_efer_lme && has_cr0_pg;
        msg("[BootEventDetector] Paging chain: CR3=%s CR4.PAE=%s EFER.LME=%s CR0.PG=%s -> %s\n",
            has_cr3 ? "set" : "MISSING",
            has_cr4_pae ? "set" : "n/a",
            has_efer_lme ? "set" : "n/a",
            has_cr0_pg ? "set" : "MISSING",
            is_longmode ? "64-bit paging" : "32-bit paging");
    }
}

void ModeTracker::enrich_events(std::vector<BootEvent *> &events) const {
    std::map<ea_t, const StateSnapshot *> snap_map;
    for (const auto &snap : snapshots_)
        snap_map[snap.address] = &snap;

    for (auto *evt : events) {
        if (evt->suppressed)
            continue;

        auto it = snap_map.find(evt->address);
        if (it != snap_map.end()) {
            const StateSnapshot *snap = it->second;
            char buf[128];
            qsnprintf(buf, sizeof(buf), " [%s->%s]",
                CpuState::mode_to_string(snap->prev_mode),
                CpuState::mode_to_string(snap->new_mode));
            evt->details += buf;
            evt->add_signal("mode transition (semantic)", true, false);
            evt->compute_tier();
        }

        if (evt->type == EventType::PMODE_ENTER
            || evt->type == EventType::PAGING_ENABLE
            || evt->type == EventType::LONGMODE_ENTER)
        {
            CpuState local_state;
            for (const auto &snap : snapshots_) {
                if (snap.address <= evt->address)
                    local_state = snap.state;
                else
                    break;
            }

            std::string state_info = " {CR0=" + local_state.cr0.decode();
            if (local_state.cr3 != 0) {
                char cr3_buf[32];
                qsnprintf(cr3_buf, sizeof(cr3_buf), " CR3=0x%llX",
                    (unsigned long long)local_state.cr3);
                state_info += cr3_buf;
            }
            state_info += " CR4=" + local_state.cr4.decode();
            state_info += " EFER=" + local_state.efer.decode();
            state_info += "}";
            evt->details += state_info;
        }
    }
}
