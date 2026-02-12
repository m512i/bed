#ifndef BOOT_EVENT_DETECTOR_UEFI_BOOT_SERVICE_DETECTOR_H
#define BOOT_EVENT_DETECTOR_UEFI_BOOT_SERVICE_DETECTOR_H

#include "detectors/base_detector.h"

class UefiBootServiceDetector : public BaseDetector {
public:
    bool matches(ea_t ea) override;
    BootEvent *analyze(ea_t ea) override;
    std::string name() const override { return "UefiBootServiceDetector"; }

private:
    struct EfiFuncInfo {
        uint32 offset;
        const char *name;
        bool critical;
    };

    static const EfiFuncInfo boot_services_[];
    const EfiFuncInfo *match_boot_service(ea_t ea) const;
};

#endif
