#include <ida.hpp>
#include <ua.hpp>
#include <bytes.hpp>
#include <segment.hpp>

#include <excpt.h>

int safe_decode_insn(insn_t *out, ea_t ea)
{

    if (ea == BADADDR)
        return 0;

    segment_t *seg = getseg(ea);
    if (seg == nullptr)
        return 0;

    if (!is_loaded(ea))
        return 0;

    __try
    {
        return decode_insn(out, ea);
    }
    __except(1)
    {
        return 0;
    }
}
