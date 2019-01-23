#ifndef TRAFICANALYZER_USER_FACADE_H
#define TRAFICANALYZER_USER_FACADE_H

#include <iostream>
#include <tins/tins.h>
#include "http_handler.h"

using namespace Tins;

class UserFacade {
public:
    UserFacade(char *deviceName, HttpHandler *handler, SnifferConfiguration configuration);

    void getPacket() {
        sniffer.sniff_loop([this](Tins::PDU &pdu) {
            static int packet_counter = 0;
            packet_counter++;
            //Packet number
            std::cout << "Packet number: " << packet_counter << std::endl;
            handler_->HttpParsePacket(pdu);
            checkTCP(pdu);
            checkDNS(pdu);

            return true;
        });
    }

    ~UserFacade();

private:
    Tins::Sniffer sniffer{nullptr};
    HttpHandler *handler_{nullptr};

    void checkDNS(Tins::PDU &pdu) {

        const UDP &udp = pdu.rfind_pdu<UDP>();
        // source and destination port should be equal 53
        if (udp.sport() == 53 || udp.dport() == 53) {
            DNS dns = pdu.rfind_pdu<RawPDU>().to<DNS>();
            for (const auto &query : dns.queries()) {
                std::cout << query.dname() << std::endl;
            }
        }
    }

    void checkTCP(PDU &pdu) {
        const Tins::IP &ip = pdu.rfind_pdu<Tins::IP>();
        const TCP &tcp = pdu.rfind_pdu<TCP>();
        std::cout << ip.src_addr() << ':' << tcp.sport() << " -> "
                  << ip.dst_addr() << ':' << tcp.dport() << std::endl;
    }
};

UserFacade::UserFacade(char *deviceName, HttpHandler *handler, SnifferConfiguration configuration) : sniffer(Tins::Sniffer(deviceName, configuration)),
                                                                                                     handler_(handler) {
    std::cout << "Sniffing device: " << deviceName << std::endl;
}

#endif //TRAFICANALYZER_USER_FACADE_H
