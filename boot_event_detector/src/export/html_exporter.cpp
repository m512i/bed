#include <ida.hpp>
#include <nalt.hpp>
#include <lines.hpp>
#include <bytes.hpp>
#include <ua.hpp>

#include "export/html_exporter.h"
#include "core/safe_decode.h"
#include <cstdio>
#include <ctime>

std::string HtmlExporter::escape_html(const std::string &s) {
    std::string result;
    result.reserve(s.size() + 20);
    for (char c : s) {
        switch (c) {
            case '<':  result += "&lt;"; break;
            case '>':  result += "&gt;"; break;
            case '&':  result += "&amp;"; break;
            case '"':  result += "&quot;"; break;
            default:   result += c; break;
        }
    }
    return result;
}

std::string HtmlExporter::get_timestamp() {
    time_t now = time(nullptr);
    struct tm *t = localtime(&now);
    char buf[64];
    qsnprintf(buf, sizeof(buf), "%04d-%02d-%02d %02d:%02d:%02d",
        t->tm_year + 1900, t->tm_mon + 1, t->tm_mday,
        t->tm_hour, t->tm_min, t->tm_sec);
    return std::string(buf);
}

std::string HtmlExporter::get_binary_name() {
    char buf[MAXSTR];
    get_root_filename(buf, sizeof(buf));
    return std::string(buf);
}

std::string HtmlExporter::get_disasm_snippet(ea_t addr, int lines_before, int lines_after) {
    std::string snippet;

    ea_t start = addr;
    for (int i = 0; i < lines_before; i++) {
        insn_t insn;
        bool found = false;
        for (ea_t try_ea = start - 1; try_ea > start - 16 && try_ea != BADADDR; try_ea--) {
            int len = safe_decode_insn(&insn, try_ea);
            if (len > 0 && try_ea + len <= start) {
                start = try_ea;
                found = true;
                break;
            }
        }
        if (!found) break;
    }

    ea_t cur = start;
    ea_t end_limit = addr + 64;
    int after_count = 0;
    bool past_target = false;

    while (cur < end_limit && cur != BADADDR) {
        insn_t insn;
        int len = safe_decode_insn(&insn, cur);
        if (len <= 0) {
            cur++;
            continue;
        }

        qstring disasm;
        generate_disasm_line(&disasm, cur, GENDSM_FORCE_CODE);
        tag_remove(&disasm);

        char line[256];
        bool is_target = (cur == addr);
        qsnprintf(line, sizeof(line), "%s  0x%04llX:  %s\n",
            is_target ? ">>>" : "   ",
            (unsigned long long)cur,
            disasm.c_str());
        snippet += line;

        cur += len;

        if (past_target) {
            after_count++;
            if (after_count >= lines_after)
                break;
        }
        if (is_target)
            past_target = true;
    }

    return snippet;
}

std::string HtmlExporter::tier_css_class(Tier t) {
    switch (t) {
        case Tier::DEFINITE: return "definite";
        case Tier::LIKELY:   return "likely";
        case Tier::POSSIBLE: return "possible";
        default:             return "unknown";
    }
}

bool HtmlExporter::export_report(
    const char *filepath,
    const std::vector<BootEvent *> &events)
{
    FILE *fp = fopen(filepath, "w");
    if (!fp)
        return false;

    std::string binary = get_binary_name();
    std::string timestamp = get_timestamp();

    std::vector<const BootEvent *> visible;
    for (auto *evt : events) {
        if (!evt->suppressed)
            visible.push_back(evt);
    }

    int definite = 0, likely = 0, possible = 0;
    for (auto *evt : visible) {
        switch (evt->tier) {
            case Tier::DEFINITE: definite++; break;
            case Tier::LIKELY:   likely++; break;
            case Tier::POSSIBLE: possible++; break;
        }
    }

    fprintf(fp, "<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n");
    fprintf(fp, "<meta charset=\"UTF-8\">\n");
    fprintf(fp, "<title>Boot Event Report - %s</title>\n", escape_html(binary).c_str());
    fprintf(fp, "<style>\n");
    fprintf(fp, "* { margin: 0; padding: 0; box-sizing: border-box; }\n");
    fprintf(fp, "body { font-family: 'Segoe UI', Consolas, monospace; background: #0d1117; color: #c9d1d9; padding: 24px; }\n");
    fprintf(fp, "h1 { color: #58a6ff; margin-bottom: 8px; font-size: 24px; }\n");
    fprintf(fp, "h2 { color: #79c0ff; margin: 24px 0 12px; font-size: 18px; border-bottom: 1px solid #30363d; padding-bottom: 6px; }\n");
    fprintf(fp, ".meta { color: #8b949e; margin-bottom: 20px; font-size: 13px; }\n");
    fprintf(fp, ".stats { display: flex; gap: 16px; margin-bottom: 24px; }\n");
    fprintf(fp, ".stat-box { background: #161b22; border: 1px solid #30363d; border-radius: 6px; padding: 12px 20px; text-align: center; }\n");
    fprintf(fp, ".stat-box .num { font-size: 28px; font-weight: bold; }\n");
    fprintf(fp, ".stat-box .lbl { font-size: 11px; color: #8b949e; text-transform: uppercase; }\n");
    fprintf(fp, ".definite .num { color: #3fb950; }\n");
    fprintf(fp, ".likely .num { color: #d29922; }\n");
    fprintf(fp, ".possible .num { color: #f85149; }\n");
    fprintf(fp, ".event { background: #161b22; border: 1px solid #30363d; border-radius: 6px; margin-bottom: 16px; overflow: hidden; }\n");
    fprintf(fp, ".event-header { padding: 10px 16px; display: flex; justify-content: space-between; align-items: center; }\n");
    fprintf(fp, ".event-header.definite { border-left: 4px solid #3fb950; }\n");
    fprintf(fp, ".event-header.likely { border-left: 4px solid #d29922; }\n");
    fprintf(fp, ".event-header.possible { border-left: 4px solid #f85149; }\n");
    fprintf(fp, ".event-type { font-weight: bold; font-size: 15px; color: #f0f6fc; }\n");
    fprintf(fp, ".event-addr { font-family: Consolas, monospace; color: #58a6ff; font-size: 13px; }\n");
    fprintf(fp, ".event-tier { font-size: 11px; padding: 2px 8px; border-radius: 10px; font-weight: bold; }\n");
    fprintf(fp, ".event-tier.definite { background: #0d2818; color: #3fb950; }\n");
    fprintf(fp, ".event-tier.likely { background: #2d1f00; color: #d29922; }\n");
    fprintf(fp, ".event-tier.possible { background: #2d0000; color: #f85149; }\n");
    fprintf(fp, ".signals { padding: 8px 16px; font-size: 13px; }\n");
    fprintf(fp, ".signal { margin: 2px 0; }\n");
    fprintf(fp, ".sig-match { color: #3fb950; }\n");
    fprintf(fp, ".sig-miss { color: #f85149; }\n");
    fprintf(fp, ".disasm { background: #0d1117; border-top: 1px solid #30363d; padding: 10px 16px; font-family: Consolas, monospace; font-size: 12px; white-space: pre; overflow-x: auto; color: #8b949e; line-height: 1.5; }\n");
    fprintf(fp, ".disasm .highlight { color: #f0f6fc; background: #1f2937; font-weight: bold; }\n");
    fprintf(fp, ".seq-tag { font-size: 11px; color: #8b949e; background: #21262d; padding: 1px 6px; border-radius: 8px; margin-left: 8px; }\n");
    fprintf(fp, "</style>\n</head>\n<body>\n");

    fprintf(fp, "<h1>Boot Event Report</h1>\n");
    fprintf(fp, "<div class=\"meta\">Binary: <strong>%s</strong> &mdash; %s &mdash; %d events</div>\n",
        escape_html(binary).c_str(), timestamp.c_str(), (int)visible.size());

    fprintf(fp, "<div class=\"stats\">\n");
    fprintf(fp, "  <div class=\"stat-box definite\"><div class=\"num\">%d</div><div class=\"lbl\">Definite</div></div>\n", definite);
    fprintf(fp, "  <div class=\"stat-box likely\"><div class=\"num\">%d</div><div class=\"lbl\">Likely</div></div>\n", likely);
    fprintf(fp, "  <div class=\"stat-box possible\"><div class=\"num\">%d</div><div class=\"lbl\">Possible</div></div>\n", possible);
    fprintf(fp, "  <div class=\"stat-box\"><div class=\"num\" style=\"color:#58a6ff\">%d</div><div class=\"lbl\">Total</div></div>\n", (int)visible.size());
    fprintf(fp, "</div>\n");

    fprintf(fp, "<h2>Detected Events</h2>\n");

    for (size_t i = 0; i < visible.size(); i++) {
        const BootEvent *evt = visible[i];
        std::string cls = tier_css_class(evt->tier);

        fprintf(fp, "<div class=\"event\">\n");
        fprintf(fp, "  <div class=\"event-header %s\">\n", cls.c_str());
        fprintf(fp, "    <div><span class=\"event-type\">%s</span>", BootEvent::type_to_string(evt->type));
        if (evt->sequence_id >= 0)
            fprintf(fp, " <span class=\"seq-tag\">seq#%d</span>", evt->sequence_id);
        fprintf(fp, "</div>\n");
        fprintf(fp, "    <div><span class=\"event-addr\">0x%llX</span> ", (unsigned long long)evt->address);
        fprintf(fp, "<span class=\"event-tier %s\">%s</span></div>\n", cls.c_str(), BootEvent::tier_to_string(evt->tier));
        fprintf(fp, "  </div>\n");

        if (!evt->signals.empty()) {
            fprintf(fp, "  <div class=\"signals\">\n");
            for (const auto &sig : evt->signals) {
                fprintf(fp, "    <div class=\"signal\"><span class=\"%s\">%s</span> %s%s</div>\n",
                    sig.matched ? "sig-match" : "sig-miss",
                    sig.matched ? "&#10003;" : "&#10007;",
                    escape_html(sig.name).c_str(),
                    sig.required ? "" : " <span style=\"color:#8b949e\">(optional)</span>");
            }
            fprintf(fp, "  </div>\n");
        }

        std::string disasm = get_disasm_snippet(evt->address, 3, 3);
        if (!disasm.empty()) {
            fprintf(fp, "  <div class=\"disasm\">");

            std::string html_disasm;
            size_t pos = 0;
            while (pos < disasm.size()) {
                size_t nl = disasm.find('\n', pos);
                if (nl == std::string::npos) nl = disasm.size();
                std::string line = disasm.substr(pos, nl - pos);
                if (line.substr(0, 3) == ">>>") {
                    html_disasm += "<span class=\"highlight\">";
                    html_disasm += escape_html(line);
                    html_disasm += "</span>\n";
                } else {
                    html_disasm += escape_html(line) + "\n";
                }
                pos = nl + 1;
            }
            fprintf(fp, "%s", html_disasm.c_str());
            fprintf(fp, "</div>\n");
        }

        fprintf(fp, "</div>\n");
    }

    fprintf(fp, "</body>\n</html>\n");
    fclose(fp);
    return true;
}
