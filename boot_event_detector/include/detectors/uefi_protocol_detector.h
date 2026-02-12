#ifndef BOOT_EVENT_DETECTOR_UEFI_PROTOCOL_DETECTOR_H
#define BOOT_EVENT_DETECTOR_UEFI_PROTOCOL_DETECTOR_H

#include "detectors/base_detector.h"

class UefiProtocolDetector : public BaseDetector {
public:
    bool matches(ea_t ea) override;
    BootEvent *analyze(ea_t ea) override;
    std::string name() const override { return "UefiProtocolDetector"; }

    struct GuidEntry {
        uint32 data1;
        uint16 data2;
        uint16 data3;
        uint8  data4[8];
        const char *name;
    };

    static const GuidEntry known_guids_[];

private:
    const GuidEntry *match_guid(ea_t ea) const;
};

#endif
