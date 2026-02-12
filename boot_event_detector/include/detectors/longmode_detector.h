#ifndef BOOT_EVENT_DETECTOR_LONGMODE_DETECTOR_H
#define BOOT_EVENT_DETECTOR_LONGMODE_DETECTOR_H

#include "detectors/base_detector.h"

class LongModeDetector : public BaseDetector {
public:
    bool matches(ea_t ea) override;
    BootEvent *analyze(ea_t ea) override;
    std::string name() const override { return "LongModeDetector"; }

private:

    bool is_efer_write(ea_t ea) const;

    bool has_pae_nearby(ea_t ea, int range = 30) const;

    bool has_cr0_pg_nearby(ea_t ea, int range = 30) const;

    bool has_far_jump_ahead(ea_t ea, int lookahead = 15) const;
};

#endif
