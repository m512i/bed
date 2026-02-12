#include "ui/timeline_view.h"
#include <algorithm>

const int TimelineView::widths_[] = { 6, 12, 16, 10, 50 };

const char *const TimelineView::header_[] = {
    "#",
    "Address",
    "Type",
    "Tier",
    "Flow"
};

TimelineView::TimelineView()
    : chooser_t(
        CH_CAN_REFRESH | CH_RESTORE | CH_ATTRS,
        qnumber(widths_),
        widths_,
        header_,
        "Boot Timeline")
    , is_open_(false)
{
    icon = 56;
}

TimelineView::~TimelineView() {
}

void TimelineView::set_events(const std::vector<BootEvent *> &events) {
    entries_.clear();

    std::vector<BootEvent *> sorted;
    for (auto *evt : events) {
        if (!evt->suppressed)
            sorted.push_back(evt);
    }
    std::sort(sorted.begin(), sorted.end(),
        [](const BootEvent *a, const BootEvent *b) { return a->address < b->address; });

    for (size_t i = 0; i < sorted.size(); i++) {
        const BootEvent *evt = sorted[i];
        TimelineEntry entry;
        entry.address = evt->address;
        entry.type = evt->type;
        entry.tier = evt->tier;
        entry.sequence_id = evt->sequence_id;
        entry.arrow_to = -1;

        entry.label = evt->get_signal_summary();
        if (!evt->details.empty()) {
            if (!entry.label.empty()) entry.label += "  ";
            entry.label += evt->details;
        }

        entries_.push_back(entry);
    }

    for (size_t i = 0; i < entries_.size(); i++) {
        if (entries_[i].sequence_id < 0)
            continue;

        for (size_t j = i + 1; j < entries_.size(); j++) {
            if (entries_[j].sequence_id == entries_[i].sequence_id) {
                entries_[i].arrow_to = (int)j;
                break;
            }
        }
    }
}

void TimelineView::show() {
    if (is_open_) {
        refresh_chooser("Boot Timeline");
        return;
    }
    is_open_ = true;
    choose();
}

size_t idaapi TimelineView::get_count() const {
    return entries_.size();
}

void idaapi TimelineView::get_row(
    qstrvec_t *out,
    int *out_icon,
    chooser_item_attrs_t *out_attrs,
    size_t n) const
{
    if (n >= entries_.size())
        return;

    const auto &e = entries_[n];

    (*out)[0].sprnt("%d", (int)(n + 1));

    (*out)[1].sprnt("0x%llX", (unsigned long long)e.address);

    (*out)[2] = BootEvent::type_to_string(e.type);

    (*out)[3] = BootEvent::tier_to_string(e.tier);

    std::string flow = e.label;
    if (e.arrow_to >= 0 && e.arrow_to < (int)entries_.size()) {
        char buf[64];
        qsnprintf(buf, sizeof(buf), "  \xe2\x86\x92 #%d (%s)",
            e.arrow_to + 1,
            BootEvent::type_to_string(entries_[e.arrow_to].type));
        flow += buf;
    }
    (*out)[4] = flow.c_str();

    if (out_icon) {
        switch (e.type) {
            case EventType::GDT_LOAD:
            case EventType::IDT_LOAD:      *out_icon = 57; break;
            case EventType::PMODE_ENTER:    *out_icon = 58; break;
            case EventType::PAGING_ENABLE:  *out_icon = 59; break;
            case EventType::LONGMODE_ENTER: *out_icon = 60; break;
            case EventType::A20_ENABLE:     *out_icon = 61; break;
            case EventType::BIOS_DISK_READ: *out_icon = 62; break;
            case EventType::VIDEO_MODE_SWITCH: *out_icon = 63; break;
            case EventType::MEMORY_MAP_QUERY:  *out_icon = 64; break;
            case EventType::SEGMENT_SETUP:
            case EventType::STACK_SETUP:    *out_icon = 65; break;
            default:                        *out_icon = 56; break;
        }
    }

    if (out_attrs) {
        switch (e.tier) {
            case Tier::DEFINITE: out_attrs->color = 0xC0FFC0; break;
            case Tier::LIKELY:   out_attrs->color = 0xC0C0FF; break;
            case Tier::POSSIBLE: out_attrs->color = 0xFFC0C0; break;
        }

        if (e.sequence_id >= 0) {

            out_attrs->color = (out_attrs->color & 0xFFFF00) | 0xFF;
        }
    }
}

ea_t idaapi TimelineView::get_ea(size_t n) const {
    if (n < entries_.size())
        return entries_[n].address;
    return BADADDR;
}

TimelineView::cbret_t idaapi TimelineView::enter(size_t n) {
    if (n < entries_.size())
        jumpto(entries_[n].address);
    return cbret_t();
}

void idaapi TimelineView::closed() {
    is_open_ = false;
}
