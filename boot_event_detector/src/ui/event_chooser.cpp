#include "ui/event_chooser.h"
#include "export/json_exporter.h"

const int EventChooser::widths_[] = { 12, 16, 12, 60 };

const char *const EventChooser::header_[] = {
    "Address",
    "Type",
    "Tier",
    "Signals"
};

EventChooser::EventChooser()
    : chooser_t(
        CH_CAN_REFRESH | CH_RESTORE | CH_ATTRS,
        qnumber(widths_),
        widths_,
        header_,
        "Boot Events")
    , is_open_(false)
{
    icon = 56;
}

void EventChooser::rebuild_visible() {
    visible_.clear();
    const auto &events = scanner_.get_events();
    for (size_t i = 0; i < events.size(); i++) {
        if (!events[i]->suppressed)
            visible_.push_back(i);
    }
}

EventChooser::~EventChooser() {
}

void EventChooser::do_scan() {
    scanner_.scan_all();
    rebuild_visible();

    if (is_open_)
        refresh_chooser("Boot Events");
}

void EventChooser::show() {
    if (is_open_) {

        refresh_chooser("Boot Events");
        return;
    }
    is_open_ = true;
    choose();
}

void EventChooser::export_json() {
    const auto &events = scanner_.get_events();
    if (events.empty()) {
        info("No events to export. Run a scan first.");
        return;
    }

    const char *filename = ask_file(true, "*.json", "Export Boot Events to JSON");
    if (filename) {
        if (JsonExporter::export_events(filename, events)) {
            msg("[BootEventDetector] Exported %d events to %s\n",
                (int)events.size(), filename);
            info("Exported %d events to:\n%s", (int)events.size(), filename);
        } else {
            warning("Failed to export events to %s", filename);
        }
    }
}

size_t idaapi EventChooser::get_count() const {
    return visible_.size();
}

void idaapi EventChooser::get_row(
    qstrvec_t *out,
    int *out_icon,
    chooser_item_attrs_t *out_attrs,
    size_t n) const
{
    if (n >= visible_.size())
        return;

    const auto &events = scanner_.get_events();
    const BootEvent *evt = events[visible_[n]];

    (*out)[0].sprnt("0x%llX", (unsigned long long)evt->address);

    (*out)[1] = BootEvent::type_to_string(evt->type);

    if (evt->sequence_id >= 0)
        (*out)[2].sprnt("%s seq#%d", BootEvent::tier_to_string(evt->tier), evt->sequence_id);
    else
        (*out)[2] = BootEvent::tier_to_string(evt->tier);

    std::string col3 = evt->get_signal_summary();
    if (!evt->details.empty()) {
        if (!col3.empty()) col3 += "  ";
        col3 += evt->details;
    }
    (*out)[3] = col3.c_str();

    if (out_icon) {
        switch (evt->type) {
            case EventType::GDT_LOAD:
            case EventType::IDT_LOAD:
                *out_icon = 57;
                break;
            case EventType::PMODE_ENTER:
                *out_icon = 58;
                break;
            case EventType::PAGING_ENABLE:
                *out_icon = 59;
                break;
            case EventType::LONGMODE_ENTER:
                *out_icon = 60;
                break;
            case EventType::A20_ENABLE:
                *out_icon = 61;
                break;
            case EventType::BIOS_DISK_READ:
                *out_icon = 62;
                break;
            case EventType::VIDEO_MODE_SWITCH:
                *out_icon = 63;
                break;
            case EventType::MEMORY_MAP_QUERY:
                *out_icon = 64;
                break;
            case EventType::SEGMENT_SETUP:
            case EventType::STACK_SETUP:
                *out_icon = 65;
                break;
            case EventType::STAGE_DETECT:
                *out_icon = 66;
                break;
            case EventType::UEFI_BOOT_SERVICE:
            case EventType::UEFI_PROTOCOL:
                *out_icon = 67;
                break;
            case EventType::MULTIBOOT_HEADER:
                *out_icon = 68;
                break;
            case EventType::PE_LOADER:
                *out_icon = 69;
                break;
            default:
                *out_icon = 56;
                break;
        }
    }

    if (out_attrs) {
        switch (evt->tier) {
            case Tier::DEFINITE:
                out_attrs->color = 0xC0FFC0;
                break;
            case Tier::LIKELY:
                out_attrs->color = 0xC0C0FF;
                break;
            case Tier::POSSIBLE:
                out_attrs->color = 0xFFC0C0;
                break;
        }
    }
}

ea_t idaapi EventChooser::get_ea(size_t n) const {
    if (n < visible_.size()) {
        const auto &events = scanner_.get_events();
        return events[visible_[n]]->address;
    }
    return BADADDR;
}

chooser_t::cbret_t idaapi EventChooser::enter(size_t n) {
    if (n < visible_.size()) {
        const auto &events = scanner_.get_events();
        jumpto(events[visible_[n]]->address);
    }
    return cbret_t();
}

void EventChooser::refresh() {
    rebuild_visible();
    if (is_open_)
        refresh_chooser("Boot Events");
}

void idaapi EventChooser::closed() {
    is_open_ = false;
}
