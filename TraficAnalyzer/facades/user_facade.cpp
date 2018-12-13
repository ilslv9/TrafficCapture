#include <bits/functexcept.h>
#include <iostream>
#include "user_facade.h"

user_facade::user_facade() {
    dev = pcap_lookupdev(errbuf);
    if (dev == NULL) {
        std::__throw_runtime_error("Couldn't find default device");
    }
    std::cout << "Target device: " << dev;
};
