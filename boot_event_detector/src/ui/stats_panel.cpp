#include "ui/stats_panel.h"
#include <kernwin.hpp>
#include <map>

void StatsPanel::show(const std::vector<BootEvent *> &events) {

    int total = 0, suppressed = 0;
    int definite = 0, likely = 0, possible = 0;
    std::map<EventType, int> type_counts;
    int sequences = 0;
    std::set<int> seq_ids;

    for (auto *evt : events) {
        if (evt->suppressed) {
            suppressed++;
            continue;
        }
        total++;
        switch (evt->tier) {
            case Tier::DEFINITE: definite++; break;
            case Tier::LIKELY:   likely++; break;
            case Tier::POSSIBLE: possible++; break;
        }
        type_counts[evt->type]++;
        if (evt->sequence_id >= 0)
            seq_ids.insert(evt->sequence_id);
    }
    sequences = (int)seq_ids.size();

    bool has_realmode = type_counts.count(EventType::SEGMENT_SETUP)
                     || type_counts.count(EventType::STACK_SETUP)
                     || type_counts.count(EventType::VIDEO_MODE_SWITCH)
                     || type_counts.count(EventType::BIOS_DISK_READ);
    bool has_a20 = type_counts.count(EventType::A20_ENABLE) > 0;
    bool has_pmode = type_counts.count(EventType::PMODE_ENTER) > 0;
    bool has_paging = type_counts.count(EventType::PAGING_ENABLE) > 0;
    bool has_longmode = type_counts.count(EventType::LONGMODE_ENTER) > 0;

    qstring msg_text;
    msg_text.sprnt(
        "=== Boot Event Statistics ===\n\n"
        "Events: %d detected (%d suppressed)\n"
        "Sequences: %d linked\n\n"
        "--- Tier Distribution ---\n"
        "  DEFINITE:  %d\n"
        "  LIKELY:    %d\n"
        "  POSSIBLE:  %d\n\n"
        "--- Event Types ---\n",
        total, suppressed, sequences,
        definite, likely, possible);

    for (auto &pair : type_counts) {
        msg_text.cat_sprnt("  %-20s  %d\n",
            BootEvent::type_to_string(pair.first), pair.second);
    }

    msg_text += "\n--- Detected Boot Stages ---\n";
    if (has_realmode)  msg_text += "  [+] Real Mode initialization\n";
    if (has_a20)       msg_text += "  [+] A20 gate enable\n";
    if (has_pmode)     msg_text += "  [+] Protected Mode entry\n";
    if (has_paging)    msg_text += "  [+] Paging enabled\n";
    if (has_longmode)  msg_text += "  [+] Long Mode (64-bit) entry\n";

    if (!has_realmode && !has_pmode && !has_longmode)
        msg_text += "  (no clear boot stages detected)\n";

    msg_text += "\n--- Boot Flow ---\n  ";
    std::vector<std::string> stages;
    if (has_realmode)  stages.push_back("Real Mode");
    if (has_a20)       stages.push_back("A20");
    if (has_pmode)     stages.push_back("Protected Mode");
    if (has_paging)    stages.push_back("Paging");
    if (has_longmode)  stages.push_back("Long Mode");

    for (size_t i = 0; i < stages.size(); i++) {
        if (i > 0) msg_text += " -> ";
        msg_text += stages[i].c_str();
    }
    msg_text += "\n";

    info("%s", msg_text.c_str());
}
