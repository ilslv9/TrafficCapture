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
        std::cout << "Target device: " << dev << std::endl;
    }

    pcap_t *createSession(int snaplen, int promisc, int to_ms) {
        handle = pcap_open_live(dev, snaplen, promisc, to_ms, errbuf);
        if (handle == nullptr) {
            std::__throw_runtime_error("Couldn't start session with device");
        }
        return handle;
    }

    void setFilter() {
        if (pcap_compile(handle, &fp, "port 53", 0, net) == -1) {
            std::__throw_runtime_error("Couldn't compile filter");
        }
        if (pcap_setfilter(handle, &fp) == -1) {
            std::__throw_runtime_error("Couldn't install filter");
        }
        std::cout << "Filter setting succesfully" << std::endl;
    }

    u_char getPacket() {
        std::cout << "Wait packet..." << std::endl;
        auto id = pcap_next(handle, &header);
        std::cout << "Packet captured succesfully. "
                  << "Packet length: " << header.len << " "
                  << "Header length: " << header.caplen << std::endl;
        return *id;
    }

    ~UserFacade() {
        delete dev;
    }

private:
    pcap_t *handle{nullptr}; //дескриптор сессии
    char *dev{nullptr}; //устройство
    char errbuf[PCAP_ERRBUF_SIZE]; //буффер ошибок
    bpf_program fp;//Фильтр
    bpf_u_int32 net;//Ip устройства
    struct pcap_pkthdr header;//Заголовок PCAP
};


#endif //TRAFICANALYZER_USER_FACADE_H
