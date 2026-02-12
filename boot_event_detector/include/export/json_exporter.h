#ifndef BOOT_EVENT_DETECTOR_JSON_EXPORTER_H
#define BOOT_EVENT_DETECTOR_JSON_EXPORTER_H

#include "core/event.h"
#include <vector>
#include <string>

class JsonExporter {
public:

    static bool export_events(
        const char *filepath,
        const std::vector<BootEvent *> &events);

private:

    static std::string escape_json(const std::string &s);

    static std::string get_timestamp();

    static std::string get_binary_name();
};

#endif
