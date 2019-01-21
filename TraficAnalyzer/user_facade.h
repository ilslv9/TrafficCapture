#ifndef TRAFICANALYZER_USER_FACADE_H
#define TRAFICANALYZER_USER_FACADE_H


#include <pcap.h>

class UserFacade {
public:
    UserFacade() {
        dev = pcap_lookupdev(errbuf);
        if (dev == nullptr) {
            std::__throw_runtime_error("Couldn't find default device");
        }
        std::cout << "Target device: " << dev;
    }

    pcap_t *createSession(int snaplen, int promisc, int to_ms) {
        handle = pcap_open_live(dev, snaplen, promisc, to_ms, errbuf);
        if (handle == nullptr) {
            std::__throw_runtime_error("Couldn't start session with device");
        }
        return handle;
    }

    void setFilter() {

    }

    ~UserFacade() {
        delete dev;
    }

private:
    pcap_t *handle{nullptr};
    char *dev{nullptr};
    char errbuf[PCAP_ERRBUF_SIZE];
};


#endif //TRAFICANALYZER_USER_FACADE_H
