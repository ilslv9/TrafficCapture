#include <iostream>
#include "pcap.h"

int main(int argc, char *argv[]) {
    char *dev, errbuf[PCAP_ERRBUF_SIZE];

    dev = pcap_lookupdev(errbuf);
    if (dev == NULL) {
        std::__throw_runtime_error("Couldn't find default device");
    }
    std::cout << dev;
}