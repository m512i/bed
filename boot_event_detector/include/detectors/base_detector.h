#ifndef BOOT_EVENT_DETECTOR_BASE_DETECTOR_H
#define BOOT_EVENT_DETECTOR_BASE_DETECTOR_H

#include "core/event.h"
#include <string>
#include <memory>

class BaseDetector {
public:
    virtual ~BaseDetector() = default;

    virtual bool matches(ea_t ea) = 0;

    virtual BootEvent *analyze(ea_t ea) = 0;

    virtual std::string name() const = 0;
};

#endif
