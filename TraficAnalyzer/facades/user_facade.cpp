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

pcap_t *user_facade::createSession(int snaplen, int promisc, int to_ms) {
    pcap_t *toReturn = pcap_open_live(dev, snaplen, promisc, to_ms, errbuf);
    if (toReturn == NULL) {
        std::__throw_runtime_error("Couldn't start session with device");
    }
    return toReturn;
}
