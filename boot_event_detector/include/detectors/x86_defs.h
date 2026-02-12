#ifndef BOOT_EVENT_DETECTOR_X86_DEFS_H
#define BOOT_EVENT_DETECTOR_X86_DEFS_H

#include <ida.hpp>
#include <ua.hpp>
#include <bytes.hpp>

enum x86_insn_type_t
{
    X86_null    = 0,
    X86_int     = 58,
    X86_jmp     = 98,
    X86_jmpfi   = 99,
    X86_jmpni   = 100,
    X86_lgdt    = 109,
    X86_lidt    = 110,
    X86_mov     = 134,
    X86_movsp   = 135,
    X86_out     = 144,
    X86_in      = 54,
    X86_wrmsr   = 246,
};

#define X86_o_crreg  o_idpspec2

enum x86_reg_t
{
    X86_R_ax  = 0,
    X86_R_cx  = 1,
    X86_R_dx  = 2,
    X86_R_bx  = 3,
    X86_R_sp  = 4,
    X86_R_bp  = 5,
    X86_R_si  = 6,
    X86_R_di  = 7,

    X86_R_al  = 16,
    X86_R_cl  = 17,
    X86_R_dl  = 18,
    X86_R_bl  = 19,

    X86_R_es  = 29,
    X86_R_cs  = 30,
    X86_R_ss  = 31,
    X86_R_ds  = 32,
    X86_R_fs  = 33,
    X86_R_gs  = 34,
};

enum x86_cr_t
{
    X86_CR0 = 0,
    X86_CR2 = 2,
    X86_CR3 = 3,
    X86_CR4 = 4,
};

#endif
