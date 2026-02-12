#ifndef BOOT_EVENT_DETECTOR_GRAPH_OVERLAY_H
#define BOOT_EVENT_DETECTOR_GRAPH_OVERLAY_H

#include <ida.hpp>
#include "core/event.h"
#include <vector>

class GraphOverlay {
public:

    static void apply(const std::vector<BootEvent *> &events);

    static void clear(const std::vector<BootEvent *> &events);
};

#endif
