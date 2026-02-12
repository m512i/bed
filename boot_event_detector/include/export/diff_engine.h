#ifndef BOOT_EVENT_DETECTOR_DIFF_ENGINE_H
#define BOOT_EVENT_DETECTOR_DIFF_ENGINE_H

#include <ida.hpp>
#include <kernwin.hpp>
#include "core/event.h"
#include <vector>
#include <string>

struct DiffEntry {
    std::string status;
    std::string type;
    std::string addr_a;
    std::string addr_b;
    std::string tier_a;
    std::string tier_b;
    std::string details;
};

class DiffEngine {
public:

    static bool compare(
        const std::vector<BootEvent *> &current,
        const char *json_path,
        std::vector<DiffEntry> &results);

private:
    struct JsonEvent {
        std::string address;
        std::string type;
        std::string tier;
    };

    static bool parse_json_events(const char *path, std::vector<JsonEvent> &out);
};

class DiffChooser : public chooser_t {
public:
    DiffChooser();
    virtual ~DiffChooser();

    void set_results(const std::vector<DiffEntry> &results, const std::string &other_name);
    void show();

protected:
    size_t idaapi get_count() const newapi;
    void idaapi get_row(
        qstrvec_t *out,
        int *out_icon,
        chooser_item_attrs_t *out_attrs,
        size_t n) const newapi;
    void idaapi closed() newapi;

    static const int widths_[];
    static const char *const header_[];

private:
    std::vector<DiffEntry> results_;
    std::string title_;
    bool is_open_;
};

#endif
