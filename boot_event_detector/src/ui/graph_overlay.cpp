#include "ui/graph_overlay.h"
#include <kernwin.hpp>
#include <graph.hpp>
#include <funcs.hpp>
#include <gdl.hpp>

static bgcolor_t tier_color(Tier t) {
    switch (t) {
        case Tier::DEFINITE: return 0x80FF80;
        case Tier::LIKELY:   return 0xFFCC80;
        case Tier::POSSIBLE: return 0x8080FF;
        default:             return 0xFFFFFF;
    }
}

void GraphOverlay::apply(const std::vector<BootEvent *> &events) {
    int colored = 0;

    for (auto *evt : events) {
        if (evt->suppressed)
            continue;

        func_t *func = get_func(evt->address);
        if (!func)
            continue;

        node_info_t ni;
        ni.bg_color = tier_color(evt->tier);
        ni.frame_color = (evt->tier == Tier::DEFINITE) ? 0x00AA00 : 0x0000AA;

        qflow_chart_t fc;
        fc.create("", func, func->start_ea, func->end_ea, FC_NOEXT);

        for (int i = 0; i < fc.size(); i++) {
            const qbasic_block_t &block = fc.blocks[i];
            if (evt->address >= block.start_ea && evt->address < block.end_ea) {
                set_node_info(func->start_ea, i, ni, NIF_BG_COLOR | NIF_FRAME_COLOR);
                colored++;
                break;
            }
        }
    }

    if (colored > 0) {
        msg("[BootEventDetector] Graph overlay: colored %d nodes\n", colored);
        refresh_idaview_anyway();
    } else {
        msg("[BootEventDetector] Graph overlay: no function nodes found (raw binary?)\n");
    }
}

void GraphOverlay::clear(const std::vector<BootEvent *> &events) {
    int cleared = 0;

    for (auto *evt : events) {
        if (evt->suppressed)
            continue;

        func_t *func = get_func(evt->address);
        if (!func)
            continue;

        qflow_chart_t fc;
        fc.create("", func, func->start_ea, func->end_ea, FC_NOEXT);

        for (int i = 0; i < fc.size(); i++) {
            const qbasic_block_t &block = fc.blocks[i];
            if (evt->address >= block.start_ea && evt->address < block.end_ea) {
                clr_node_info(func->start_ea, i, NIF_BG_COLOR | NIF_FRAME_COLOR);
                cleared++;
                break;
            }
        }
    }

    if (cleared > 0) {
        msg("[BootEventDetector] Graph overlay: cleared %d nodes\n", cleared);
        refresh_idaview_anyway();
    }
}
