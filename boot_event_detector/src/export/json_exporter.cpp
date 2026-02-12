#include <ida.hpp>
#include <nalt.hpp>

#include "export/json_exporter.h"
#include <cstdio>
#include <ctime>

std::string JsonExporter::escape_json(const std::string &s) {
    std::string result;
    result.reserve(s.size() + 10);
    for (char c : s) {
        switch (c) {
            case '"':  result += "\\\""; break;
            case '\\': result += "\\\\"; break;
            case '\n': result += "\\n";  break;
            case '\r': result += "\\r";  break;
            case '\t': result += "\\t";  break;
            default:   result += c;      break;
        }
    }
    return result;
}

std::string JsonExporter::get_timestamp() {
    time_t now = time(nullptr);
    struct tm *t = localtime(&now);
    char buf[64];
    qsnprintf(buf, sizeof(buf), "%04d-%02d-%02d %02d:%02d:%02d",
        t->tm_year + 1900, t->tm_mon + 1, t->tm_mday,
        t->tm_hour, t->tm_min, t->tm_sec);
    return std::string(buf);
}

std::string JsonExporter::get_binary_name() {
    char buf[MAXSTR];
    get_root_filename(buf, sizeof(buf));
    return std::string(buf);
}

bool JsonExporter::export_events(
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

    fprintf(fp, "{\n");
    fprintf(fp, "  \"binary\": \"%s\",\n", escape_json(binary).c_str());
    fprintf(fp, "  \"scan_date\": \"%s\",\n", timestamp.c_str());
    fprintf(fp, "  \"event_count\": %d,\n", (int)visible.size());
    fprintf(fp, "  \"events\": [\n");

    for (size_t i = 0; i < visible.size(); i++) {
        const BootEvent *evt = visible[i];

        fprintf(fp, "    {\n");
        fprintf(fp, "      \"address\": \"0x%llX\",\n",
            (unsigned long long)evt->address);
        fprintf(fp, "      \"type\": \"%s\",\n",
            BootEvent::type_to_string(evt->type));
        fprintf(fp, "      \"tier\": \"%s\"",
            BootEvent::tier_to_string(evt->tier));

        if (!evt->signals.empty()) {
            fprintf(fp, ",\n      \"signals\": [\n");
            for (size_t s = 0; s < evt->signals.size(); s++) {
                const auto &sig = evt->signals[s];
                fprintf(fp, "        {\"name\": \"%s\", \"matched\": %s, \"required\": %s}",
                    escape_json(sig.name).c_str(),
                    sig.matched ? "true" : "false",
                    sig.required ? "true" : "false");
                if (s + 1 < evt->signals.size())
                    fprintf(fp, ",");
                fprintf(fp, "\n");
            }
            fprintf(fp, "      ]");
        }

        if (!evt->details.empty()) {
            fprintf(fp, ",\n      \"details\": \"%s\"",
                escape_json(evt->details).c_str());
        }

        if (evt->sequence_id >= 0) {
            fprintf(fp, ",\n      \"sequence_id\": %d", evt->sequence_id);
        }

        if (!evt->related.empty()) {
            fprintf(fp, ",\n      \"related\": [");
            for (size_t j = 0; j < evt->related.size(); j++) {
                if (j > 0) fprintf(fp, ", ");
                fprintf(fp, "\"0x%llX\"",
                    (unsigned long long)evt->related[j]);
            }
            fprintf(fp, "]");
        }

        fprintf(fp, "\n    }");
        if (i + 1 < visible.size())
            fprintf(fp, ",");
        fprintf(fp, "\n");
    }

    fprintf(fp, "  ]\n");
    fprintf(fp, "}\n");

    fclose(fp);
    return true;
}
