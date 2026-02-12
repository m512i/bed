#ifndef BOOT_EVENT_DETECTOR_SAFE_DECODE_H
#define BOOT_EVENT_DETECTOR_SAFE_DECODE_H

#include <ida.hpp>
#include <ua.hpp>
#include <bytes.hpp>

int safe_decode_insn(insn_t *out, ea_t ea);

template<typename Func>
bool walk_backward(ea_t ea, int max_bytes, Func callback)
{

    ea_t limit = (ea > (ea_t)max_bytes) ? (ea - max_bytes) : 0;
    ea_t cur = ea;
    while (cur > limit) {
        cur--;
        insn_t insn;
        int len = safe_decode_insn(&insn, cur);
        if (len <= 0)
            continue;

        if (cur + len > ea)
            continue;

        if (callback(insn, cur))
            return true;
    }
    return false;
}

template<typename Func>
bool walk_forward(ea_t ea, int max_bytes, Func callback)
{
    ea_t cur = ea;
    ea_t end = ea + max_bytes;
    while (cur < end && cur != BADADDR) {
        insn_t insn;
        int len = safe_decode_insn(&insn, cur);
        if (len <= 0) {
            cur++;
            continue;
        }

        if (callback(insn, cur))
            return true;

        cur += len;
    }
    return false;
}

#endif
