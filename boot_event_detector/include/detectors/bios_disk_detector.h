#ifndef BOOT_EVENT_DETECTOR_BIOS_DISK_DETECTOR_H
#define BOOT_EVENT_DETECTOR_BIOS_DISK_DETECTOR_H

#include "detectors/base_detector.h"

class BiosDiskDetector : public BaseDetector {
public:
    bool matches(ea_t ea) override;
    BootEvent *analyze(ea_t ea) override;
    std::string name() const override { return "BiosDiskDetector"; }

private:

    int get_ah_value(ea_t ea) const;

    int get_dl_value(ea_t ea) const;

    std::string parse_dap_info(ea_t ea) const;
};

#endif
