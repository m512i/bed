#include <ida.hpp>
#include <segment.hpp>
#include <bytes.hpp>
#include <kernwin.hpp>
#include <ua.hpp>
#include <funcs.hpp>
#include <auto.hpp>
#include <xref.hpp>
#include <intel.hpp>
#include <algorithm>

#include "core/scanner.h"
#include "core/classifier.h"
#include "detectors/descriptor_detector.h"
#include "detectors/pmode_detector.h"
#include "detectors/paging_detector.h"
#include "detectors/longmode_detector.h"
#include "detectors/a20_detector.h"
#include "detectors/bios_disk_detector.h"
#include "detectors/video_mode_detector.h"
#include "detectors/memmap_detector.h"
#include "detectors/segment_setup_detector.h"
#include "detectors/stage_detector.h"
#include "detectors/uefi_boot_service_detector.h"
#include "detectors/uefi_protocol_detector.h"
#include "detectors/multiboot_detector.h"
#include "detectors/pe_loader_detector.h"

#include "core/safe_decode.h"
#include "analysis/mode_tracker.h"
#include "analysis/descriptor_table.h"
#include "analysis/selector_resolver.h"
#include "analysis/mode_timeline.h"

Scanner::Scanner()
    : next_sequence_id_(0)
{
    register_detectors();
}

Scanner::~Scanner() {
    clear();
}

void Scanner::register_detectors() {
    detectors_.clear();

    if (config_.detect_gdt_idt)
        detectors_.push_back(std::make_unique<DescriptorDetector>());
    if (config_.detect_pmode)
        detectors_.push_back(std::make_unique<PmodeDetector>());
    if (config_.detect_paging)
        detectors_.push_back(std::make_unique<PagingDetector>());
    if (config_.detect_longmode)
        detectors_.push_back(std::make_unique<LongModeDetector>());
    if (config_.detect_a20)
        detectors_.push_back(std::make_unique<A20Detector>());
    if (config_.detect_bios_disk)
        detectors_.push_back(std::make_unique<BiosDiskDetector>());
    if (config_.detect_video_mode)
        detectors_.push_back(std::make_unique<VideoModeDetector>());
    if (config_.detect_memmap)
        detectors_.push_back(std::make_unique<MemMapDetector>());
    if (config_.detect_segment_setup)
        detectors_.push_back(std::make_unique<SegmentSetupDetector>());
    if (config_.detect_stage)
        detectors_.push_back(std::make_unique<StageDetector>());
    if (config_.detect_uefi_boot_svc)
        detectors_.push_back(std::make_unique<UefiBootServiceDetector>());
    if (config_.detect_uefi_protocol)
        detectors_.push_back(std::make_unique<UefiProtocolDetector>());
    if (config_.detect_multiboot)
        detectors_.push_back(std::make_unique<MultibootDetector>());
    if (config_.detect_pe_loader)
        detectors_.push_back(std::make_unique<PeLoaderDetector>());

    msg("[BootEventDetector] Registered %d detectors\n", (int)detectors_.size());
}

void Scanner::clear() {
    for (auto *evt : events_)
        delete evt;
    events_.clear();
}

void Scanner::scan_all() {
    clear();
    next_sequence_id_ = 0;

    register_detectors();

    int seg_count = get_segm_qty();
    if (seg_count == 0) {
        msg("[BootEventDetector] No segments found\n");
        return;
    }

    if (auto_is_ok())
        auto_wait();

    show_wait_box("Scanning for boot events...");

    for (int i = 0; i < seg_count; i++) {
        segment_t *seg = getnseg(i);
        if (!seg)
            continue;

        if (config_.range_start != 0 || config_.range_end != 0) {
            if (seg->end_ea <= config_.range_start)
                continue;
            if (config_.range_end != 0 && seg->start_ea >= config_.range_end)
                continue;
        }

        msg("[BootEventDetector] Scanning segment %d: 0x%llX - 0x%llX\n",
            i, (unsigned long long)seg->start_ea, (unsigned long long)seg->end_ea);

        scan_segment_flow(seg);
    }

    resolve_operands();
    link_sequences();
    suppress_duplicates();
    cluster_segment_setups();
    dedup_nearby_events();
    reclassify_segment_setups();
    reduce_uefi_noise();
    apply_function_context();
    run_semantic_analysis();

    for (auto *evt : events_) {
        if (!evt->suppressed)
            add_comment(evt->address, evt);
    }

    hide_wait_box();

    int visible = 0;
    for (auto *evt : events_)
        if (!evt->suppressed) visible++;

    msg("[BootEventDetector] Scan complete: %d events detected (%d after suppression)\n",
        (int)events_.size(), visible);
}

void Scanner::scan_segment_flow(segment_t *seg) {
    std::set<ea_t> visited;
    int decoded_count = 0;
    int loaded_count = 0;

    std::vector<ea_t> entry_points;
    entry_points.push_back(seg->start_ea);

    size_t func_qty = get_func_qty();
    for (size_t fi = 0; fi < func_qty; fi++) {
        func_t *f = getn_func(fi);
        if (f && f->start_ea >= seg->start_ea && f->start_ea < seg->end_ea) {
            entry_points.push_back(f->start_ea);
        }
    }

    for (ea_t entry : entry_points) {
        scan_from(entry, seg->end_ea, visited);
    }

    for (ea_t ea = seg->start_ea; ea < seg->end_ea; ) {
        if (user_cancelled()) {
            msg("[BootEventDetector] Scan cancelled by user\n");
            return;
        }

        if (visited.count(ea)) {
            ea++;
            continue;
        }

        if (!is_loaded(ea)) {
            ea++;
            continue;
        }
        loaded_count++;

        insn_t insn;
        int len = safe_decode_insn(&insn, ea);
        if (len <= 0) {
            ea++;
            continue;
        }
        decoded_count++;
        visited.insert(ea);

        for (auto &detector : detectors_) {
            if (detector->matches(ea)) {
                BootEvent *evt = detector->analyze(ea);
                if (evt) {
                    Classifier::refine(evt);
                    events_.push_back(evt);

                    msg("[BootEventDetector] Found: %s at 0x%llX (%s)\n",
                        BootEvent::type_to_string(evt->type),
                        (unsigned long long)ea,
                        BootEvent::tier_to_string(evt->tier));
                }
            }
        }

        ea += len;
    }

    std::set<ea_t> found_addrs;
    for (auto *evt : events_)
        found_addrs.insert(evt->address);

    for (ea_t ea = seg->start_ea; ea < seg->end_ea; ea++) {
        if (visited.count(ea) || found_addrs.count(ea))
            continue;
        if (!is_loaded(ea) || !is_loaded(ea + 1))
            continue;

        uint8 b0 = get_byte(ea);
        uint8 b1 = get_byte(ea + 1);

        if (b0 == 0x0F && b1 == 0x30) {
            for (auto &detector : detectors_) {
                if (detector->matches(ea)) {
                    BootEvent *evt = detector->analyze(ea);
                    if (evt) {
                        Classifier::refine(evt);
                        events_.push_back(evt);
                        found_addrs.insert(ea);

                        msg("[BootEventDetector] Found (raw scan): %s at 0x%llX (%s)\n",
                            BootEvent::type_to_string(evt->type),
                            (unsigned long long)ea,
                            BootEvent::tier_to_string(evt->tier));
                    }
                }
            }
        }
    }

    if (visited.empty()) {
        int fail_count = 0;
        ea_t limit = seg->start_ea + 0x2000;
        if (limit > seg->end_ea)
            limit = seg->end_ea;

        for (ea_t ea = seg->start_ea; ea < limit; ) {
            if (user_cancelled())
                return;
            if (!is_loaded(ea)) {
                ea++;
                fail_count++;
                if (fail_count > 64) break;
                continue;
            }

            insn_t insn;
            int len = safe_decode_insn(&insn, ea);
            if (len <= 0) {
                ea++;
                fail_count++;
                if (fail_count > 64) break;
                continue;
            }
            fail_count = 0;
            visited.insert(ea);

            for (auto &detector : detectors_) {
                if (detector->matches(ea)) {
                    BootEvent *evt = detector->analyze(ea);
                    if (evt) {
                        Classifier::refine(evt);
                        events_.push_back(evt);

                        msg("[BootEventDetector] Found (brute sweep): %s at 0x%llX (%s)\n",
                            BootEvent::type_to_string(evt->type),
                            (unsigned long long)ea,
                            BootEvent::tier_to_string(evt->tier));
                    }
                }
            }
            ea += len;
        }
    }

    msg("[BootEventDetector] Segment: %d bytes visited via flow + linear fallback\n",
        (int)visited.size());
}

void Scanner::scan_from(ea_t start, ea_t seg_end, std::set<ea_t> &visited) {

    std::vector<ea_t> worklist;
    worklist.push_back(start);

    while (!worklist.empty()) {
        ea_t ea = worklist.back();
        worklist.pop_back();

        while (ea < seg_end && ea != BADADDR) {
            if (visited.count(ea))
                break;
            if (!is_loaded(ea))
                break;

            insn_t insn;
            int len = safe_decode_insn(&insn, ea);
            if (len <= 0)
                break;

            visited.insert(ea);

            if (user_cancelled())
                return;

            if (visited.size() % 500 == 0) {
                replace_wait_box("Scanning: 0x%llX (%d events found)",
                    (unsigned long long)ea, (int)events_.size());
            }

            for (auto &detector : detectors_) {
                if (detector->matches(ea)) {
                    BootEvent *evt = detector->analyze(ea);
                    if (evt) {
                        Classifier::refine(evt);
                        events_.push_back(evt);

                        msg("[BootEventDetector] Found: %s at 0x%llX (%s)\n",
                            BootEvent::type_to_string(evt->type),
                            (unsigned long long)ea,
                            BootEvent::tier_to_string(evt->tier));
                    }
                }
            }

            bool is_unconditional_jmp = (insn.itype == NN_jmp
                || insn.itype == NN_jmpfi || insn.itype == NN_jmpni);
            bool is_conditional_jmp = (insn.itype >= NN_ja && insn.itype <= NN_jz);
            bool is_call = (insn.itype == NN_call || insn.itype == NN_callfi
                || insn.itype == NN_callni);
            bool is_ret = (insn.itype == NN_retn || insn.itype == NN_retf);
            bool is_hlt = (insn.itype == NN_hlt);

            if (is_ret || is_hlt)
                break;

            if ((is_conditional_jmp || is_call) && insn.ops[0].type == o_near) {
                ea_t target = insn.ops[0].addr;
                if (target >= start && target < seg_end && !visited.count(target))
                    worklist.push_back(target);
            }

            if (is_unconditional_jmp) {

                if (insn.ops[0].type == o_near || insn.ops[0].type == o_far) {
                    ea_t target = insn.ops[0].addr;
                    if (target < seg_end && !visited.count(target)) {
                        ea = target;
                        continue;
                    }
                }

                if (insn.itype == NN_jmpfi || insn.itype == NN_jmpni) {
                    ea_t next = ea + len;
                    if (next < seg_end && !visited.count(next))
                        worklist.push_back(next);
                }
                break;
            }

            ea += len;
        }
    }
}

void Scanner::add_comment(ea_t ea, const BootEvent *evt) {
    std::string cmt = evt->get_comment_text();
    if (evt->sequence_id >= 0) {
        char seq_buf[32];
        qsnprintf(seq_buf, sizeof(seq_buf), " [seq#%d]", evt->sequence_id);
        cmt += seq_buf;
    }
    set_cmt(ea, cmt.c_str(), true);
}

void Scanner::link_sequences() {

    std::vector<BootEvent *> sorted = events_;
    std::sort(sorted.begin(), sorted.end(),
        [](const BootEvent *a, const BootEvent *b) { return a->address < b->address; });

    std::map<ea_t, BootEvent *> addr_map;
    for (auto *evt : events_)
        addr_map[evt->address] = evt;

    for (size_t i = 0; i < sorted.size(); i++) {
        if (sorted[i]->type != EventType::GDT_LOAD)
            continue;

        int seq_id = -1;
        ea_t gdt_addr = sorted[i]->address;

        for (size_t j = i + 1; j < sorted.size(); j++) {
            ea_t dist = sorted[j]->address - gdt_addr;
            if (dist > 256) break;

            if (sorted[j]->type == EventType::IDT_LOAD
                || sorted[j]->type == EventType::PMODE_ENTER)
            {
                if (seq_id < 0) {
                    seq_id = next_sequence_id_++;
                    sorted[i]->sequence_id = seq_id;
                    sorted[i]->details += " [pmode sequence]";
                }
                sorted[j]->sequence_id = seq_id;
                sorted[i]->related.push_back(sorted[j]->address);
                sorted[j]->related.push_back(gdt_addr);
            }
        }
    }

    for (size_t i = 0; i < sorted.size(); i++) {
        if (sorted[i]->type != EventType::PAGING_ENABLE)
            continue;
        if (sorted[i]->sequence_id >= 0)
            continue;

        ea_t pg_addr = sorted[i]->address;
        int seq_id = -1;

        for (size_t j = i + 1; j < sorted.size(); j++) {
            ea_t dist = sorted[j]->address - pg_addr;
            if (dist > 256) break;

            if (sorted[j]->type == EventType::LONGMODE_ENTER) {
                if (seq_id < 0) {
                    seq_id = next_sequence_id_++;
                    sorted[i]->sequence_id = seq_id;
                    sorted[i]->details += " [longmode sequence]";
                }
                sorted[j]->sequence_id = seq_id;
                sorted[i]->related.push_back(sorted[j]->address);
                sorted[j]->related.push_back(pg_addr);
                sorted[j]->details += " [longmode sequence]";
            }
        }
    }

    for (size_t i = 0; i < sorted.size(); i++) {
        if (sorted[i]->type != EventType::SEGMENT_SETUP
            && sorted[i]->type != EventType::STACK_SETUP)
            continue;
        if (sorted[i]->sequence_id >= 0)
            continue;

        ea_t base_addr = sorted[i]->address;
        int seq_id = -1;

        for (size_t j = i + 1; j < sorted.size(); j++) {
            ea_t dist = sorted[j]->address - base_addr;
            if (dist > 32) break;

            if (sorted[j]->type == EventType::SEGMENT_SETUP
                || sorted[j]->type == EventType::STACK_SETUP)
            {
                if (seq_id < 0) {
                    seq_id = next_sequence_id_++;
                    sorted[i]->sequence_id = seq_id;
                }
                sorted[j]->sequence_id = seq_id;
                sorted[i]->related.push_back(sorted[j]->address);
                sorted[j]->related.push_back(base_addr);
            }
        }
    }

    for (auto *evt : events_)
        Classifier::refine(evt);

    int seq_count = next_sequence_id_;
    if (seq_count > 0)
        msg("[BootEventDetector] Linked %d event sequences\n", seq_count);
}

void Scanner::suppress_duplicates() {

    std::map<ea_t, std::vector<BootEvent *>> by_addr;
    for (auto *evt : events_)
        by_addr[evt->address].push_back(evt);

    int suppressed_count = 0;

    for (auto &pair : by_addr) {
        auto &evts = pair.second;
        if (evts.size() <= 1)
            continue;

        BootEvent *stack_evt = nullptr;
        for (auto *e : evts) {
            if (e->type == EventType::STACK_SETUP)
                stack_evt = e;
        }
        if (stack_evt) {
            for (auto *e : evts) {
                if (e->type == EventType::SEGMENT_SETUP && !e->suppressed) {
                    e->suppressed = true;
                    suppressed_count++;
                }
            }
        }

        std::map<EventType, BootEvent *> best;
        for (auto *e : evts) {
            if (e->suppressed) continue;
            auto it = best.find(e->type);
            if (it == best.end()) {
                best[e->type] = e;
            } else {

                if (e->tier < it->second->tier) {
                    it->second->suppressed = true;
                    suppressed_count++;
                    best[e->type] = e;
                } else {
                    e->suppressed = true;
                    suppressed_count++;
                }
            }
        }
    }

    for (auto *evt : events_) {
        if (evt->suppressed || evt->type != EventType::SEGMENT_SETUP)
            continue;

        if (evt->details.find("SS") == std::string::npos)
            continue;

        for (auto *other : events_) {
            if (other->suppressed || other->type != EventType::STACK_SETUP)
                continue;
            ea_t dist = (evt->address > other->address)
                ? (evt->address - other->address)
                : (other->address - evt->address);
            if (dist <= 8) {
                evt->suppressed = true;
                suppressed_count++;
                break;
            }
        }
    }

    if (suppressed_count > 0)
        msg("[BootEventDetector] Suppressed %d duplicate/redundant events\n", suppressed_count);
}

void Scanner::cluster_segment_setups() {

    std::vector<BootEvent *> sorted = events_;
    std::sort(sorted.begin(), sorted.end(),
        [](const BootEvent *a, const BootEvent *b) { return a->address < b->address; });

    int clusters_merged = 0;

    for (size_t i = 0; i < sorted.size(); i++) {
        if (sorted[i]->suppressed)
            continue;
        if (sorted[i]->type != EventType::SEGMENT_SETUP)
            continue;

        std::vector<size_t> cluster;
        cluster.push_back(i);
        ea_t base = sorted[i]->address;

        for (size_t j = i + 1; j < sorted.size(); j++) {
            if (sorted[j]->suppressed)
                continue;
            ea_t dist = sorted[j]->address - base;
            if (dist > 32)
                break;
            if (sorted[j]->type == EventType::SEGMENT_SETUP)
                cluster.push_back(j);
        }

        if (cluster.size() < 2)
            continue;

        std::vector<std::string> regs;
        for (size_t ci : cluster) {

            for (const auto &sig : sorted[ci]->signals) {
                if (sig.name.substr(0, 4) == "mov " && sig.matched) {
                    regs.push_back(sig.name.substr(4));
                }
            }
        }

        BootEvent *leader = sorted[cluster[0]];
        std::string reg_list;
        for (size_t r = 0; r < regs.size(); r++) {
            if (r > 0) reg_list += " ";
            reg_list += regs[r];
        }

        leader->signals.clear();
        leader->add_signal("segment register cluster", true);

        char count_buf[32];
        qsnprintf(count_buf, sizeof(count_buf), "cluster size: %d", (int)cluster.size());
        leader->add_signal(count_buf, true, false);

        for (const auto &r : regs) {
            std::string sig_name = "mov " + r;
            leader->add_signal(sig_name, true, false);
        }

        leader->add_signal("related instructions", !leader->related.empty(), false);

        leader->details = "registers: " + reg_list;
        ea_t window = sorted[cluster.back()]->address - leader->address;
        char win_buf[48];
        qsnprintf(win_buf, sizeof(win_buf), " | window: %d bytes", (int)window);
        leader->details += win_buf;

        leader->compute_tier();

        for (size_t ci = 1; ci < cluster.size(); ci++) {
            sorted[cluster[ci]]->suppressed = true;
            leader->related.push_back(sorted[cluster[ci]]->address);
        }

        clusters_merged++;

        i = cluster.back();
    }

    if (clusters_merged > 0)
        msg("[BootEventDetector] Clustered %d SEGMENT_SETUP groups\n", clusters_merged);
}

void Scanner::dedup_nearby_events() {
    std::vector<BootEvent *> sorted = events_;
    std::sort(sorted.begin(), sorted.end(),
        [](const BootEvent *a, const BootEvent *b) { return a->address < b->address; });

    int deduped = 0;

    for (size_t i = 0; i < sorted.size(); i++) {
        if (sorted[i]->suppressed)
            continue;

        if (sorted[i]->type == EventType::SEGMENT_SETUP
            || sorted[i]->type == EventType::STACK_SETUP)
            continue;

        for (size_t j = i + 1; j < sorted.size(); j++) {
            if (sorted[j]->suppressed)
                continue;
            ea_t dist = sorted[j]->address - sorted[i]->address;
            if (dist > 64)
                break;

            if (sorted[j]->type == sorted[i]->type) {

                BootEvent *keep, *drop;
                if (sorted[i]->tier <= sorted[j]->tier) {
                    keep = sorted[i];
                    drop = sorted[j];
                } else {
                    keep = sorted[j];
                    drop = sorted[i];
                }
                drop->suppressed = true;
                keep->related.push_back(drop->address);

                char dup_buf[64];
                qsnprintf(dup_buf, sizeof(dup_buf), " [duplicate-of 0x%llX]",
                    (unsigned long long)keep->address);
                drop->details += dup_buf;

                deduped++;
            }
        }
    }

    if (deduped > 0)
        msg("[BootEventDetector] Deduped %d nearby same-type events\n", deduped);
}

void Scanner::reclassify_segment_setups() {
    if (!config_.suppress_kernel_segments)
        return;

    std::set<ea_t> boot_addrs;
    for (auto *evt : events_) {
        if (evt->suppressed) continue;
        if (evt->type == EventType::GDT_LOAD
            || evt->type == EventType::IDT_LOAD
            || evt->type == EventType::PMODE_ENTER
            || evt->type == EventType::PAGING_ENABLE
            || evt->type == EventType::LONGMODE_ENTER
            || evt->type == EventType::A20_ENABLE)
        {
            boot_addrs.insert(evt->address);
        }
    }

    int reclassified = 0;
    int tls_converted = 0;

    for (auto *evt : events_) {
        if (evt->suppressed) continue;
        if (evt->type != EventType::SEGMENT_SETUP)
            continue;

        bool near_boot = false;
        for (ea_t ba : boot_addrs) {
            ea_t dist = (evt->address > ba) ? (evt->address - ba) : (ba - evt->address);
            if (dist <= 256) {
                near_boot = true;
                break;
            }
        }

        if (near_boot)
            continue;

        segment_t *seg = getseg(evt->address);
        bool is_64 = seg && seg->is_64bit();

        if (is_64) {
            bool fs_gs_only = true;
            for (const auto &sig : evt->signals) {
                if (sig.name.substr(0, 4) == "mov " && sig.matched) {
                    std::string reg = sig.name.substr(4);
                    if (reg != "FS" && reg != "GS")
                        fs_gs_only = false;
                }
            }

            if (evt->details.find("registers:") != std::string::npos) {
                if (evt->details.find("DS") != std::string::npos
                    || evt->details.find("ES") != std::string::npos
                    || evt->details.find("SS") != std::string::npos)
                {
                    fs_gs_only = false;
                }
            }

            if (fs_gs_only) {
                evt->type = EventType::TLS_GS_SETUP;
                evt->add_signal("near boot transition", false, true);
                evt->add_signal("64-bit segment (TLS/kernel base)", true, false);
                evt->compute_tier();
                tls_converted++;
                continue;
            }
        }

        evt->add_signal("near boot transition", false, true);
        evt->compute_tier();
        if (is_64) {
            evt->suppressed = true;
        }
        reclassified++;
    }

    if (reclassified > 0)
        msg("[BootEventDetector] Suppressed/downgraded %d non-boot SEGMENT_SETUP events\n", reclassified);
    if (tls_converted > 0)
        msg("[BootEventDetector] Reclassified %d events as TLS_GS_SETUP\n", tls_converted);
}

void Scanner::reduce_uefi_noise() {

    static const char *suppress_names[] = {
        "FreePool", "AllocatePool", "AllocatePages", "FreePages",
        "RaiseTPL", "RestoreTPL", "CreateEvent", "SetTimer",
        "WaitForEvent", "SignalEvent", "CloseEvent", "CheckEvent",
        "Stall", "GetNextMonotonicCount", "SetWatchdogTimer",
        nullptr
    };

    auto is_suppressed_service = [&](const std::string &details) -> bool {
        for (int i = 0; suppress_names[i]; i++) {

            if (details.find(suppress_names[i]) == 0)
                return true;
        }
        return false;
    };

    auto get_dedup_key = [](const BootEvent *evt) -> std::string {

        size_t bs_pos = evt->details.find("(BS+");
        size_t in_pos = evt->details.find(" in ");
        std::string offset_part, func_part;
        if (bs_pos != std::string::npos) {
            size_t end = evt->details.find(')', bs_pos);
            if (end != std::string::npos)
                offset_part = evt->details.substr(bs_pos, end - bs_pos + 1);
        }
        if (in_pos != std::string::npos) {
            func_part = evt->details.substr(in_pos + 4);
        }
        return func_part + "|" + offset_part;
    };

    int suppressed = 0;
    int deduped = 0;
    int tiered_down = 0;
    std::set<std::string> seen_keys;

    for (auto *evt : events_) {
        if (evt->suppressed) continue;
        if (evt->type != EventType::UEFI_BOOT_SERVICE) continue;

        if (is_suppressed_service(evt->details)) {
            evt->suppressed = true;
            suppressed++;
            continue;
        }

        std::string key = get_dedup_key(evt);
        if (!key.empty() && key != "|") {
            if (seen_keys.count(key)) {
                evt->suppressed = true;
                deduped++;
                continue;
            }
            seen_keys.insert(key);
        }

        bool is_critical = (evt->details.find("[CRITICAL]") != std::string::npos);
        if (!is_critical) {

            for (auto &sig : evt->signals) {
                if (sig.name == "EFI_BOOT_SERVICES call")
                    sig.matched = false;
            }
            evt->compute_tier();
            tiered_down++;
        }
    }

    if (suppressed > 0)
        msg("[BootEventDetector] Suppressed %d non-critical UEFI_BOOT_SVC events\n", suppressed);
    if (deduped > 0)
        msg("[BootEventDetector] Deduped %d duplicate UEFI_BOOT_SVC events (same function+offset)\n", deduped);
    if (tiered_down > 0)
        msg("[BootEventDetector] Tiered down %d non-critical UEFI_BOOT_SVC to lower confidence\n", tiered_down);
}

void Scanner::resolve_operands() {
    for (auto *evt : events_) {

        if (evt->type == EventType::GDT_LOAD || evt->type == EventType::IDT_LOAD) {
            insn_t insn;
            if (safe_decode_insn(&insn, evt->address) > 0) {

                if (insn.ops[0].type == o_mem || insn.ops[0].type == o_displ) {
                    ea_t desc_addr = insn.ops[0].addr;
                    if (is_loaded(desc_addr) && is_loaded(desc_addr + 5)) {
                        uint16 limit = get_word(desc_addr);
                        uint32 base = get_dword(desc_addr + 2);
                        char buf[64];
                        qsnprintf(buf, sizeof(buf), " (base=0x%X, limit=0x%X)",
                            base, limit);
                        evt->details += buf;
                        evt->related.push_back(desc_addr);
                    }
                }
            }
        }

        if (evt->type == EventType::PAGING_ENABLE) {
            bool resolved = false;
            insn_t cr3_insn;
            if (safe_decode_insn(&cr3_insn, evt->address) > 0) {

                int src_reg = cr3_insn.ops[1].reg;
                walk_backward(evt->address, 30, [&](const insn_t &insn, ea_t addr) -> bool {

                    if (insn.itype == NN_mov
                        && insn.ops[0].type == o_reg
                        && insn.ops[0].reg == src_reg
                        && insn.ops[1].type == o_imm
                        && insn.ops[1].value != 0)
                    {
                        char buf[48];
                        qsnprintf(buf, sizeof(buf), ", page_table=0x%llX",
                            (unsigned long long)insn.ops[1].value);
                        evt->details += buf;
                        resolved = true;
                        return true;
                    }

                    if (insn.itype == NN_movsp)
                        return false;

                    if (insn.itype == NN_mov
                        && insn.ops[0].type == o_reg
                        && insn.ops[0].reg == src_reg)
                        return true;
                    return false;
                });
            }

            if (!resolved) {
                ea_t limit = (evt->address > 30) ? (evt->address - 30) : 0;
                for (ea_t cur = evt->address - 1; cur >= limit && cur != BADADDR; cur--) {
                    if (!is_loaded(cur) || !is_loaded(cur + 4))
                        continue;
                    uint8 b = get_byte(cur);
                    if (b >= 0xB8 && b <= 0xBF) {
                        uint32 val = get_dword(cur + 1);
                        if (val != 0 && val != 0x80000000) {
                            char buf[48];
                            qsnprintf(buf, sizeof(buf), ", page_table=0x%X", val);
                            evt->details += buf;
                            break;
                        }
                    }
                }
            }
        }

        if (evt->type == EventType::LONGMODE_ENTER) {

            walk_backward(evt->address, 20, [&](const insn_t &insn, ea_t addr) -> bool {
                if (insn.itype == NN_or
                    && insn.ops[0].type == o_reg
                    && insn.ops[0].reg == R_ax
                    && insn.ops[1].type == o_imm)
                {
                    uint32 bits = (uint32)insn.ops[1].value;
                    std::string bit_info;
                    if (bits & 0x100) bit_info += " LME";
                    if (bits & 0x800) bit_info += " NXE";
                    if (bits & 0x001) bit_info += " SCE";
                    if (!bit_info.empty())
                        evt->details += " (bits:" + bit_info + ")";
                    return true;
                }
                return false;
            });
        }
    }
}

void Scanner::apply_function_context() {
    for (auto *evt : events_) {
        if (evt->suppressed)
            continue;

        func_t *func = get_func(evt->address);
        if (func) {
            qstring func_name;
            if (get_func_name(&func_name, func->start_ea) > 0 && !func_name.empty()) {
                evt->details += " in ";
                evt->details += func_name.c_str();
            }

            evt->add_signal("inside IDA function", true, false);
            evt->compute_tier();
        }
    }
}

void Scanner::run_semantic_analysis() {
    ModeTracker tracker;
    tracker.run(events_);

    std::vector<DescriptorTableInfo> gdts;
    for (auto *evt : events_) {
        if (evt->suppressed)
            continue;
        if (evt->type != EventType::GDT_LOAD)
            continue;

        insn_t insn;
        if (safe_decode_insn(&insn, evt->address) <= 0)
            continue;
        if (insn.ops[0].type != o_mem && insn.ops[0].type != o_displ)
            continue;

        ea_t desc_ptr = insn.ops[0].addr;
        DescriptorTableInfo gdt = DescriptorTableResolver::parse_gdt(desc_ptr);
        if (gdt.valid()) {
            DescriptorTableResolver::annotate(gdt, true);

            for (const auto &desc : gdt.entries) {
                if (desc.selector == 0 && desc.base == 0 && desc.limit == 0)
                    continue;
                char buf[128];
                qsnprintf(buf, sizeof(buf), " [GDT#%d: %s]",
                    desc.selector / 8, desc.summary().c_str());
                evt->details += buf;
            }

            gdts.push_back(gdt);
        }
    }

    SelectorResolver resolver;
    if (!gdts.empty())
        resolver.set_gdt(gdts.back());
    resolver.scan_far_refs(events_);
    resolver.enrich_events(events_);

    tracker.validate_paging_sequence(events_);
    tracker.enrich_events(events_);

    ModeTimeline timeline;
    timeline.build(tracker.get_snapshots(), gdts);
    timeline.log();
    timeline.add_comments();
}
