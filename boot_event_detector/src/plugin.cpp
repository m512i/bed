#include <ida.hpp>
#include <idp.hpp>
#include <loader.hpp>
#include <kernwin.hpp>
#include <moves.hpp>

#include "ui/event_chooser.h"
#include "ui/timeline_view.h"
#include "ui/graph_overlay.h"
#include "ui/stats_panel.h"
#include "ui/scan_config.h"
#include "export/html_exporter.h"
#include "export/diff_engine.h"

struct open_chooser_action_t : public action_handler_t
{
    EventChooser **chooser_ptr;
    open_chooser_action_t(EventChooser **p) : chooser_ptr(p) {}

    int idaapi activate(action_activation_ctx_t *) override
    {
        if (!*chooser_ptr)
        {
            ScanConfig cfg;
            if (!ScanConfig::show_dialog(cfg))
                return 1;

            *chooser_ptr = new EventChooser();
            (*chooser_ptr)->get_scanner().set_config(cfg);
            (*chooser_ptr)->do_scan();
        }
        (*chooser_ptr)->show();
        return 1;
    }

    action_state_t idaapi update(action_update_ctx_t *) override
    {
        return AST_ENABLE_ALWAYS;
    }
};

struct rescan_action_t : public action_handler_t
{
    EventChooser **chooser_ptr;
    rescan_action_t(EventChooser **p) : chooser_ptr(p) {}

    int idaapi activate(action_activation_ctx_t *) override
    {
        ScanConfig cfg;
        if (*chooser_ptr)
            cfg = (*chooser_ptr)->get_scanner().get_config();

        if (!ScanConfig::show_dialog(cfg))
            return 1;

        if (!*chooser_ptr)
        {
            *chooser_ptr = new EventChooser();
        }
        (*chooser_ptr)->get_scanner().set_config(cfg);
        (*chooser_ptr)->do_scan();
        (*chooser_ptr)->show();
        return 1;
    }

    action_state_t idaapi update(action_update_ctx_t *) override
    {
        return AST_ENABLE_ALWAYS;
    }
};

struct export_json_action_t : public action_handler_t
{
    EventChooser **chooser_ptr;
    export_json_action_t(EventChooser **p) : chooser_ptr(p) {}

    int idaapi activate(action_activation_ctx_t *) override
    {
        if (*chooser_ptr)
            (*chooser_ptr)->export_json();
        else
            info("No scan results. Open Boot Events first (Ctrl+Shift+B).");
        return 1;
    }

    action_state_t idaapi update(action_update_ctx_t *) override
    {
        return AST_ENABLE_ALWAYS;
    }
};

struct timeline_action_t : public action_handler_t
{
    EventChooser **chooser_ptr;
    TimelineView *timeline = nullptr;
    timeline_action_t(EventChooser **p) : chooser_ptr(p) {}

    int idaapi activate(action_activation_ctx_t *) override
    {
        if (!*chooser_ptr) {
            info("No scan results. Open Boot Events first (Ctrl+Shift+B).");
            return 1;
        }
        if (!timeline)
            timeline = new TimelineView();
        timeline->set_events((*chooser_ptr)->get_scanner().get_events());
        timeline->show();
        return 1;
    }

    action_state_t idaapi update(action_update_ctx_t *) override
    { return AST_ENABLE_ALWAYS; }
};

struct graph_overlay_action_t : public action_handler_t
{
    EventChooser **chooser_ptr;
    bool active = false;
    graph_overlay_action_t(EventChooser **p) : chooser_ptr(p) {}

    int idaapi activate(action_activation_ctx_t *) override
    {
        if (!*chooser_ptr) {
            info("No scan results. Open Boot Events first (Ctrl+Shift+B).");
            return 1;
        }
        const auto &events = (*chooser_ptr)->get_scanner().get_events();
        if (active) {
            GraphOverlay::clear(events);
            active = false;
        } else {
            GraphOverlay::apply(events);
            active = true;
        }
        return 1;
    }

    action_state_t idaapi update(action_update_ctx_t *) override
    { return AST_ENABLE_ALWAYS; }
};

struct html_export_action_t : public action_handler_t
{
    EventChooser **chooser_ptr;
    html_export_action_t(EventChooser **p) : chooser_ptr(p) {}

    int idaapi activate(action_activation_ctx_t *) override
    {
        if (!*chooser_ptr) {
            info("No scan results. Open Boot Events first (Ctrl+Shift+B).");
            return 1;
        }
        const char *filename = ask_file(true, "*.html", "Export Boot Event HTML Report");
        if (filename) {
            const auto &events = (*chooser_ptr)->get_scanner().get_events();
            if (HtmlExporter::export_report(filename, events)) {
                msg("[BootEventDetector] HTML report exported to %s\n", filename);
                info("HTML report exported to:\n%s", filename);
            } else {
                warning("Failed to export HTML report to %s", filename);
            }
        }
        return 1;
    }

    action_state_t idaapi update(action_update_ctx_t *) override
    { return AST_ENABLE_ALWAYS; }
};

struct diff_action_t : public action_handler_t
{
    EventChooser **chooser_ptr;
    DiffChooser *diff_chooser = nullptr;
    diff_action_t(EventChooser **p) : chooser_ptr(p) {}

    int idaapi activate(action_activation_ctx_t *) override
    {
        if (!*chooser_ptr) {
            info("No scan results. Open Boot Events first (Ctrl+Shift+B).");
            return 1;
        }
        const char *filename = ask_file(false, "*.json", "Select JSON export to compare against");
        if (filename) {
            std::vector<DiffEntry> results;
            if (DiffEngine::compare((*chooser_ptr)->get_scanner().get_events(), filename, results)) {
                if (!diff_chooser)
                    diff_chooser = new DiffChooser();
                diff_chooser->set_results(results, filename);
                diff_chooser->show();
                msg("[BootEventDetector] Diff: %d entries\n", (int)results.size());
            } else {
                warning("Failed to parse JSON file: %s", filename);
            }
        }
        return 1;
    }

    action_state_t idaapi update(action_update_ctx_t *) override
    { return AST_ENABLE_ALWAYS; }
};

struct toggle_segments_action_t : public action_handler_t
{
    EventChooser **chooser_ptr;
    bool showing_all = false;
    toggle_segments_action_t(EventChooser **p) : chooser_ptr(p) {}

    int idaapi activate(action_activation_ctx_t *) override
    {
        if (!*chooser_ptr) {
            info("No scan results. Open Boot Events first (Ctrl+Shift+B).");
            return 1;
        }
        const auto &events = (*chooser_ptr)->get_scanner().get_events();
        int toggled_seg = 0;
        int toggled_uefi = 0;
        showing_all = !showing_all;
        for (auto *evt : events) {

            if (evt->type == EventType::SEGMENT_SETUP
                || evt->type == EventType::TLS_GS_SETUP)
            {
                bool was_reclassified = false;
                for (const auto &sig : evt->signals) {
                    if (sig.name == "near boot transition" && !sig.matched) {
                        was_reclassified = true;
                        break;
                    }
                }
                if (was_reclassified) {
                    evt->suppressed = !showing_all;
                    toggled_seg++;
                }
            }

            if (evt->type == EventType::UEFI_BOOT_SERVICE) {
                bool is_critical = (evt->details.find("[CRITICAL]") != std::string::npos);
                if (!is_critical) {
                    evt->suppressed = !showing_all;
                    toggled_uefi++;
                }
            }
        }
        (*chooser_ptr)->refresh();
        msg("[BootEventDetector] %s %d SEGMENT_SETUP + %d UEFI_BOOT_SVC suppressed events\n",
            showing_all ? "Showing" : "Hiding", toggled_seg, toggled_uefi);
        return 1;
    }

    action_state_t idaapi update(action_update_ctx_t *) override
    { return AST_ENABLE_ALWAYS; }
};

struct stats_action_t : public action_handler_t
{
    EventChooser **chooser_ptr;
    stats_action_t(EventChooser **p) : chooser_ptr(p) {}

    int idaapi activate(action_activation_ctx_t *) override
    {
        if (!*chooser_ptr) {
            info("No scan results. Open Boot Events first (Ctrl+Shift+B).");
            return 1;
        }
        StatsPanel::show((*chooser_ptr)->get_scanner().get_events());
        return 1;
    }

    action_state_t idaapi update(action_update_ctx_t *) override
    { return AST_ENABLE_ALWAYS; }
};

struct bookmarks_action_t : public action_handler_t
{
    EventChooser **chooser_ptr;
    bookmarks_action_t(EventChooser **p) : chooser_ptr(p) {}

    int idaapi activate(action_activation_ctx_t *) override
    {
        if (!*chooser_ptr) {
            info("No scan results. Open Boot Events first (Ctrl+Shift+B).");
            return 1;
        }
        TWidget *w = find_widget("IDA View-A");
        if (!w)
            w = get_current_widget();
        if (!w) {
            warning("No disassembly view found. Please open IDA View-A first.");
            return 1;
        }

        const auto &events = (*chooser_ptr)->get_scanner().get_events();
        int added = 0;
        uint32 slot = 0;
        for (auto *evt : events) {
            if (evt->suppressed)
                continue;

            idaplace_t ipl(evt->address, 0);
            lochist_entry_t e;
            e.set_place(&ipl);
            renderer_info_t &ri = e.renderer_info();
            ri.rtype = TCCRT_FLAT;
            ri.pos.cx = 0;
            ri.pos.cy = 0;

            qstring desc;
            desc.sprnt("[Boot] %s: %s",
                BootEvent::type_to_string(evt->type),
                evt->details.c_str());

            uint32 result = bookmarks_t::mark(e, slot, nullptr, desc.c_str(), w);
            if (result != BOOKMARKS_BAD_INDEX) {
                added++;
                slot = result + 1;
            }
        }
        msg("[BootEventDetector] Added %d bookmarks\n", added);

        open_bookmarks_window(w);

        info("Added %d bookmarks for visible boot events.", added);
        return 1;
    }

    action_state_t idaapi update(action_update_ctx_t *) override
    { return AST_ENABLE_ALWAYS; }
};

struct boot_event_plugin_t : public plugmod_t
{
    EventChooser *chooser = nullptr;

    open_chooser_action_t    open_handler;
    rescan_action_t          rescan_handler;
    export_json_action_t     export_handler;
    timeline_action_t        timeline_handler;
    graph_overlay_action_t   graph_handler;
    html_export_action_t     html_handler;
    diff_action_t            diff_handler;
    toggle_segments_action_t toggle_seg_handler;
    stats_action_t           stats_handler;
    bookmarks_action_t       bookmarks_handler;

    boot_event_plugin_t()
        : open_handler(&chooser)
        , rescan_handler(&chooser)
        , export_handler(&chooser)
        , timeline_handler(&chooser)
        , graph_handler(&chooser)
        , html_handler(&chooser)
        , diff_handler(&chooser)
        , toggle_seg_handler(&chooser)
        , stats_handler(&chooser)
        , bookmarks_handler(&chooser)
    {

        const action_desc_t acts[] =
        {
            ACTION_DESC_LITERAL_PLUGMOD(
                "boot_event:open",
                "Boot Events - Open",
                &open_handler,
                this,
                "Ctrl+Shift+B",
                "Open Boot Event Detector chooser",
                -1),
            ACTION_DESC_LITERAL_PLUGMOD(
                "boot_event:rescan",
                "Boot Events - Rescan",
                &rescan_handler,
                this,
                "Ctrl+Shift+R",
                "Rescan binary for boot events",
                -1),
            ACTION_DESC_LITERAL_PLUGMOD(
                "boot_event:export",
                "Boot Events - Export JSON",
                &export_handler,
                this,
                "Ctrl+Shift+E",
                "Export boot events to JSON",
                -1),
            ACTION_DESC_LITERAL_PLUGMOD(
                "boot_event:timeline",
                "Boot Events - Timeline",
                &timeline_handler,
                this,
                "Ctrl+Shift+T",
                "Show boot event timeline",
                -1),
            ACTION_DESC_LITERAL_PLUGMOD(
                "boot_event:graph",
                "Boot Events - Graph Overlay",
                &graph_handler,
                this,
                "Ctrl+Shift+G",
                "Highlight boot events on graph",
                -1),
            ACTION_DESC_LITERAL_PLUGMOD(
                "boot_event:html",
                "Boot Events - Export HTML",
                &html_handler,
                this,
                "Ctrl+Alt+H",
                "Export rich HTML report",
                -1),
            ACTION_DESC_LITERAL_PLUGMOD(
                "boot_event:diff",
                "Boot Events - Diff",
                &diff_handler,
                this,
                "Ctrl+Alt+D",
                "Compare against another JSON export",
                -1),
            ACTION_DESC_LITERAL_PLUGMOD(
                "boot_event:toggle_segments",
                "Boot Events - Toggle Suppressed",
                &toggle_seg_handler,
                this,
                "Ctrl+Shift+F",
                "Show/hide suppressed SEGMENT_SETUP and UEFI_BOOT_SVC events",
                -1),
            ACTION_DESC_LITERAL_PLUGMOD(
                "boot_event:stats",
                "Boot Events - Statistics",
                &stats_handler,
                this,
                "Ctrl+Shift+S",
                "Show boot event statistics",
                -1),
            ACTION_DESC_LITERAL_PLUGMOD(
                "boot_event:bookmarks",
                "Boot Events - Add Bookmarks",
                &bookmarks_handler,
                this,
                "Ctrl+Alt+B",
                "Add IDA bookmarks at all visible boot events",
                -1),
        };

        for (size_t i = 0; i < qnumber(acts); i++)
            register_action(acts[i]);

        attach_action_to_menu("View/Open subviews/", "boot_event:open", SETMENU_APP);
        attach_action_to_menu("View/Open subviews/", "boot_event:timeline", SETMENU_APP);
        attach_action_to_menu("Edit/", "boot_event:rescan", SETMENU_APP);
        attach_action_to_menu("Edit/", "boot_event:graph", SETMENU_APP);
        attach_action_to_menu("Edit/", "boot_event:toggle_segments", SETMENU_APP);
        attach_action_to_menu("Edit/", "boot_event:stats", SETMENU_APP);
        attach_action_to_menu("File/Produce file/", "boot_event:export", SETMENU_APP);
        attach_action_to_menu("File/Produce file/", "boot_event:html", SETMENU_APP);
        attach_action_to_menu("File/Produce file/", "boot_event:diff", SETMENU_APP);
        attach_action_to_menu("Edit/", "boot_event:bookmarks", SETMENU_APP);

        msg("[BootEventDetector] Plugin loaded. Press Ctrl+Shift+B to open.\n");
    }

    ~boot_event_plugin_t()
    {
        unregister_action("boot_event:open");
        unregister_action("boot_event:rescan");
        unregister_action("boot_event:export");
        unregister_action("boot_event:timeline");
        unregister_action("boot_event:graph");
        unregister_action("boot_event:html");
        unregister_action("boot_event:diff");
        unregister_action("boot_event:toggle_segments");
        unregister_action("boot_event:stats");
        unregister_action("boot_event:bookmarks");

        chooser = nullptr;
        msg("[BootEventDetector] Plugin unloaded.\n");
    }

    bool idaapi run(size_t) override
    {
        if (!chooser)
        {
            ScanConfig cfg;
            if (!ScanConfig::show_dialog(cfg))
                return true;

            chooser = new EventChooser();
            chooser->get_scanner().set_config(cfg);
            chooser->do_scan();
        }
        chooser->show();
        return true;
    }
};

static plugmod_t *idaapi init()
{
    return new boot_event_plugin_t();
}

plugin_t PLUGIN =
{
    IDP_INTERFACE_VERSION,
    PLUGIN_MULTI,
    init,
    nullptr,
    nullptr,
    "Boot Event Detector - Detects CPU mode switches in firmware/bootloaders",
    "Automatically detects GDT/IDT loads, protected mode entry, paging, "
    "long mode transitions, and A20 gate enable in boot code.",
    "BootEventDetector",
    "Ctrl+Shift+B"
};
