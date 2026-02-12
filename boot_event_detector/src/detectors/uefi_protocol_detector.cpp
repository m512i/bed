#include "detectors/uefi_protocol_detector.h"
#include <bytes.hpp>
#include <segment.hpp>
#include "core/safe_decode.h"

const UefiProtocolDetector::GuidEntry UefiProtocolDetector::known_guids_[] = {

    { 0x5B1B31A1, 0x9562, 0x11D2, {0x8E,0x3F,0x00,0xA0,0xC9,0x69,0x72,0x3B}, "EFI_LOADED_IMAGE_PROTOCOL" },

    { 0x09576E91, 0x6D3F, 0x11D2, {0x8E,0x39,0x00,0xA0,0xC9,0x69,0x72,0x3B}, "EFI_DEVICE_PATH_PROTOCOL" },

    { 0x387477C1, 0x69C7, 0x11D2, {0x8E,0x39,0x00,0xA0,0xC9,0x69,0x72,0x3B}, "EFI_SIMPLE_TEXT_INPUT" },

    { 0x387477C2, 0x69C7, 0x11D2, {0x8E,0x39,0x00,0xA0,0xC9,0x69,0x72,0x3B}, "EFI_SIMPLE_TEXT_OUTPUT" },

    { 0x964E5B22, 0x6459, 0x11D2, {0x8E,0x39,0x00,0xA0,0xC9,0x69,0x72,0x3B}, "EFI_SIMPLE_FILE_SYSTEM" },

    { 0x964E5B21, 0x6459, 0x11D2, {0x8E,0x39,0x00,0xA0,0xC9,0x69,0x72,0x3B}, "EFI_BLOCK_IO" },

    { 0xCE345171, 0xBA0B, 0x11D2, {0x8E,0x4F,0x00,0xA0,0xC9,0x69,0x72,0x3B}, "EFI_DISK_IO" },

    { 0x9042A9DE, 0x23DC, 0x4A38, {0x96,0xFB,0x7A,0xDE,0xD0,0x80,0x51,0x6A}, "EFI_GRAPHICS_OUTPUT" },

    { 0x4CF5B200, 0x68B8, 0x4CA5, {0x9E,0xEC,0xB2,0x3E,0x3F,0x50,0x02,0x9A}, "EFI_PCI_IO" },

    { 0x8868E871, 0xE4F1, 0x11D3, {0xBC,0x22,0x00,0x80,0xC7,0x3C,0x88,0x81}, "EFI_ACPI_20_TABLE" },

    { 0x8BE4DF61, 0x93CA, 0x11D2, {0xAA,0x0D,0x00,0xE0,0x98,0x03,0x2B,0x8C}, "EFI_GLOBAL_VARIABLE" },

    { 0x3FDDA605, 0xA76E, 0x4F46, {0xAD,0x29,0x12,0xF4,0x53,0x1B,0x3D,0x08}, "EFI_MP_SERVICES" },

    { 0, 0, 0, {0}, nullptr }
};

const UefiProtocolDetector::GuidEntry *UefiProtocolDetector::match_guid(ea_t ea) const {
    if (!is_loaded(ea) || !is_loaded(ea + 15))
        return nullptr;

    uint32 d1 = get_dword(ea);
    uint16 d2 = get_word(ea + 4);
    uint16 d3 = get_word(ea + 6);

    for (int i = 0; known_guids_[i].name; i++) {
        const GuidEntry &g = known_guids_[i];
        if (g.data1 != d1 || g.data2 != d2 || g.data3 != d3)
            continue;

        bool d4_match = true;
        for (int j = 0; j < 8; j++) {
            if (get_byte(ea + 8 + j) != g.data4[j]) {
                d4_match = false;
                break;
            }
        }
        if (d4_match)
            return &g;
    }
    return nullptr;
}

bool UefiProtocolDetector::matches(ea_t ea) {

    if (ea & 3)
        return false;
    return match_guid(ea) != nullptr;
}

BootEvent *UefiProtocolDetector::analyze(ea_t ea) {
    const GuidEntry *guid = match_guid(ea);
    if (!guid)
        return nullptr;

    auto *evt = new BootEvent(ea, EventType::UEFI_PROTOCOL, "");

    evt->add_signal("known UEFI GUID", true);

    char guid_str[80];
    qsnprintf(guid_str, sizeof(guid_str),
        "{%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X}",
        guid->data1, guid->data2, guid->data3,
        guid->data4[0], guid->data4[1], guid->data4[2], guid->data4[3],
        guid->data4[4], guid->data4[5], guid->data4[6], guid->data4[7]);

    evt->add_signal(guid->name, true, false);
    evt->details = guid->name;
    evt->details += " ";
    evt->details += guid_str;

    evt->compute_tier();
    return evt;
}
