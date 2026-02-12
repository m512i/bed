#include "core/classifier.h"

void Classifier::refine(BootEvent *evt) {
    if (!evt)
        return;

    if (!evt->related.empty()) {
        bool already_has = false;
        for (const auto &sig : evt->signals) {
            if (sig.name == "related instructions")
                already_has = true;
        }
        if (!already_has)
            evt->add_signal("related instructions", true, false);
    }

    evt->compute_tier();
}
