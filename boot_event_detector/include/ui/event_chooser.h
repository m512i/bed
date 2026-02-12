#ifndef BOOT_EVENT_DETECTOR_EVENT_CHOOSER_H
#define BOOT_EVENT_DETECTOR_EVENT_CHOOSER_H

#include <ida.hpp>
#include <kernwin.hpp>
#include "core/event.h"
#include "core/scanner.h"
#include <vector>

class EventChooser : public chooser_t {
public:
    EventChooser();
    virtual ~EventChooser();

    void do_scan();

    void show();

    void export_json();

    const Scanner &get_scanner() const { return scanner_; }
    Scanner &get_scanner() { return scanner_; }

    void refresh();

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
    Scanner scanner_;
    bool is_open_;
    std::vector<size_t> visible_;

    void rebuild_visible();
};

#endif
