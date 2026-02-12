#ifndef BOOT_EVENT_DETECTOR_HTML_EXPORTER_H
#define BOOT_EVENT_DETECTOR_HTML_EXPORTER_H

#include "core/event.h"
#include <vector>
#include <string>

class HtmlExporter {
public:
    static bool export_report(
        const char *filepath,
        const std::vector<BootEvent *> &events);

private:
    static std::string escape_html(const std::string &s);
    static std::string get_timestamp();
    static std::string get_binary_name();
    static std::string get_disasm_snippet(ea_t addr, int lines_before, int lines_after);
    static std::string tier_css_class(Tier t);
};

#endif
