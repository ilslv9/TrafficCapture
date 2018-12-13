#ifndef TRAFICANALYZER_USER_FACADE_H
#define TRAFICANALYZER_USER_FACADE_H


#include <pcap.h>

class user_facade {
public:
    user_facade();

//    pcap_t createSession(int snaplen, int promisc, int to_ms, char *ebuf);

    ~user_facade();

private:
    char *dev{nullptr};
    char errbuf[PCAP_ERRBUF_SIZE];
};


#endif //TRAFICANALYZER_USER_FACADE_H
