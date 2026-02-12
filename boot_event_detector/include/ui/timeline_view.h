#ifndef BOOT_EVENT_DETECTOR_TIMELINE_VIEW_H
#define BOOT_EVENT_DETECTOR_TIMELINE_VIEW_H

#include <ida.hpp>
#include <kernwin.hpp>
#include "core/event.h"
#include <vector>

class TimelineView : public chooser_t {
public:
    TimelineView();
    virtual ~TimelineView();

    void set_events(const std::vector<BootEvent *> &events);
    void show();

protected:
    size_t idaapi get_count() const newapi;
    void idaapi get_row(
        qstrvec_t *out,
        int *out_icon,
        chooser_item_attrs_t *out_attrs,
        size_t n) const newapi;
    ea_t idaapi get_ea(size_t n) const newapi;
    cbret_t idaapi enter(size_t n) newapi;
    void idaapi closed() newapi;

    static const int widths_[];
    static const char *const header_[];

private:
    struct TimelineEntry {
        ea_t address;
        EventType type;
        Tier tier;
        std::string label;
        int sequence_id;
        int arrow_to;
    };

    std::vector<TimelineEntry> entries_;
    bool is_open_;
};

#endif
