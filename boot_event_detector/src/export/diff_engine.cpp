#include "export/diff_engine.h"
#include <cstdio>
#include <cstring>
#include <algorithm>

bool DiffEngine::parse_json_events(const char *path, std::vector<JsonEvent> &out) {
    FILE *fp = fopen(path, "r");
    if (!fp)
        return false;

    fseek(fp, 0, SEEK_END);
    long sz = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    if (sz <= 0 || sz > 10 * 1024 * 1024) {
        fclose(fp);
        return false;
    }

    std::string content(sz, '\0');
    fread(&content[0], 1, sz, fp);
    fclose(fp);

    size_t pos = 0;
    while (pos < content.size()) {

        size_t obj = content.find("\"type\"", pos);
        if (obj == std::string::npos)
            break;

        JsonEvent evt;

        size_t colon = content.find(':', obj);
        size_t q1 = content.find('"', colon + 1);
        size_t q2 = content.find('"', q1 + 1);
        if (q1 != std::string::npos && q2 != std::string::npos)
            evt.type = content.substr(q1 + 1, q2 - q1 - 1);

        size_t addr_key = content.rfind("\"address\"", obj);
        if (addr_key != std::string::npos && obj - addr_key < 200) {
            size_t ac = content.find(':', addr_key);
            size_t aq1 = content.find('"', ac + 1);
            size_t aq2 = content.find('"', aq1 + 1);
            if (aq1 != std::string::npos && aq2 != std::string::npos)
                evt.address = content.substr(aq1 + 1, aq2 - aq1 - 1);
        }

        size_t tier_key = content.find("\"tier\"", obj);
        if (tier_key != std::string::npos && tier_key - obj < 200) {
            size_t tc = content.find(':', tier_key);
            size_t tq1 = content.find('"', tc + 1);
            size_t tq2 = content.find('"', tq1 + 1);
            if (tq1 != std::string::npos && tq2 != std::string::npos)
                evt.tier = content.substr(tq1 + 1, tq2 - tq1 - 1);
        }

        if (!evt.type.empty())
            out.push_back(evt);

        pos = obj + 6;
    }

    return !out.empty();
}

bool DiffEngine::compare(
    const std::vector<BootEvent *> &current,
    const char *json_path,
    std::vector<DiffEntry> &results)
{
    results.clear();

    std::vector<JsonEvent> other;
    if (!parse_json_events(json_path, other))
        return false;

    std::vector<std::pair<std::string, std::string>> cur_types;
    std::vector<std::string> cur_addrs;
    for (auto *evt : current) {
        if (evt->suppressed) continue;
        cur_types.push_back({
            BootEvent::type_to_string(evt->type),
            BootEvent::tier_to_string(evt->tier)
        });
        char buf[32];
        qsnprintf(buf, sizeof(buf), "0x%llX", (unsigned long long)evt->address);
        cur_addrs.push_back(buf);
    }

    std::vector<bool> cur_matched(cur_types.size(), false);
    std::vector<bool> other_matched(other.size(), false);

    size_t oi = 0;
    for (size_t ci = 0; ci < cur_types.size() && oi < other.size(); ci++) {
        if (cur_types[ci].first == other[oi].type) {
            DiffEntry d;
            if (cur_addrs[ci] == other[oi].address && cur_types[ci].second == other[oi].tier) {
                d.status = "MATCH";
            } else {
                d.status = "CHANGED";
            }
            d.type = cur_types[ci].first;
            d.addr_a = cur_addrs[ci];
            d.addr_b = other[oi].address;
            d.tier_a = cur_types[ci].second;
            d.tier_b = other[oi].tier;
            results.push_back(d);
            cur_matched[ci] = true;
            other_matched[oi] = true;
            oi++;
        }
    }

    for (size_t ci = 0; ci < cur_types.size(); ci++) {
        if (cur_matched[ci]) continue;
        DiffEntry d;
        d.status = "ADDED";
        d.type = cur_types[ci].first;
        d.addr_a = cur_addrs[ci];
        d.tier_a = cur_types[ci].second;
        d.details = "New in current binary";
        results.push_back(d);
    }

    for (size_t oi2 = 0; oi2 < other.size(); oi2++) {
        if (other_matched[oi2]) continue;
        DiffEntry d;
        d.status = "REMOVED";
        d.type = other[oi2].type;
        d.addr_b = other[oi2].address;
        d.tier_b = other[oi2].tier;
        d.details = "Missing from current binary";
        results.push_back(d);
    }

    return true;
}

const int DiffChooser::widths_[] = { 10, 16, 12, 12, 12, 30 };

const char *const DiffChooser::header_[] = {
    "Status",
    "Type",
    "Addr (A)",
    "Addr (B)",
    "Tier",
    "Details"
};

DiffChooser::DiffChooser()
    : chooser_t(
        CH_CAN_REFRESH | CH_RESTORE | CH_ATTRS,
        qnumber(widths_),
        widths_,
        header_,
        "Boot Event Diff")
    , is_open_(false)
{
    icon = 56;
}

DiffChooser::~DiffChooser() {
}

void DiffChooser::set_results(const std::vector<DiffEntry> &results, const std::string &other_name) {
    results_ = results;
    title_ = "Diff vs " + other_name;
}

void DiffChooser::show() {
    if (is_open_) {
        refresh_chooser("Boot Event Diff");
        return;
    }
    is_open_ = true;
    choose();
}

size_t idaapi DiffChooser::get_count() const {
    return results_.size();
}

void idaapi DiffChooser::get_row(
    qstrvec_t *out,
    int *out_icon,
    chooser_item_attrs_t *out_attrs,
    size_t n) const
{
    if (n >= results_.size())
        return;

    const auto &d = results_[n];

    (*out)[0] = d.status.c_str();
    (*out)[1] = d.type.c_str();
    (*out)[2] = d.addr_a.empty() ? "-" : d.addr_a.c_str();
    (*out)[3] = d.addr_b.empty() ? "-" : d.addr_b.c_str();

    if (!d.tier_a.empty() && !d.tier_b.empty() && d.tier_a != d.tier_b) {
        std::string tier_str = d.tier_a + " -> " + d.tier_b;
        (*out)[4] = tier_str.c_str();
    } else if (!d.tier_a.empty()) {
        (*out)[4] = d.tier_a.c_str();
    } else {
        (*out)[4] = d.tier_b.c_str();
    }

    (*out)[5] = d.details.c_str();

    if (out_icon)
        *out_icon = 56;

    if (out_attrs) {
        if (d.status == "MATCH")
            out_attrs->color = 0xC0FFC0;
        else if (d.status == "ADDED")
            out_attrs->color = 0xFFFFC0;
        else if (d.status == "REMOVED")
            out_attrs->color = 0xFFC0C0;
        else if (d.status == "CHANGED")
            out_attrs->color = 0xC0C0FF;
    }
}

void idaapi DiffChooser::closed() {
    is_open_ = false;
}
