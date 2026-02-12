#ifndef BOOT_EVENT_DETECTOR_CLASSIFIER_H
#define BOOT_EVENT_DETECTOR_CLASSIFIER_H

#include "core/event.h"

class Classifier {
public:

    static void refine(BootEvent *evt);
};

#endif
