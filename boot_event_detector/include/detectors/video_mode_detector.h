#ifndef BOOT_EVENT_DETECTOR_VIDEO_MODE_DETECTOR_H
#define BOOT_EVENT_DETECTOR_VIDEO_MODE_DETECTOR_H

#include "detectors/base_detector.h"

class VideoModeDetector : public BaseDetector {
public:
    bool matches(ea_t ea) override;
    BootEvent *analyze(ea_t ea) override;
    std::string name() const override { return "VideoModeDetector"; }

private:

    int get_ah_value(ea_t ea) const;
    int get_ax_value(ea_t ea) const;
    int get_al_value(ea_t ea) const;
};

#endif
