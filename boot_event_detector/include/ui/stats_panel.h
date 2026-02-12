#ifndef BOOT_EVENT_DETECTOR_STATS_PANEL_H
#define BOOT_EVENT_DETECTOR_STATS_PANEL_H

#include <ida.hpp>
#include "core/event.h"
#include <vector>

class StatsPanel {
public:

    static void show(const std::vector<BootEvent *> &events);
};

#endif
