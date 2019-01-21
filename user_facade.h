#ifndef TRAFICANALYZER_USER_FACADE_H
#define TRAFICANALYZER_USER_FACADE_H

#include <iostream>
#include <tins/tins.h>

using namespace Tins;

class UserFacade {
public:
    UserFacade(char *deviceName);

    void getPacket() {
        sniffer.sniff_loop(handlePacket);
    }

    ~UserFacade();

private:
    Tins::Sniffer sniffer{nullptr};

    static bool handlePacket(Tins::PDU &pdu) {
        static int packet_counter = 0;
        packet_counter++;
        //Packet number
        std::cout << "Packet number: " << packet_counter << std::endl;

        checkTCP(pdu);
        checkDNS(pdu);


        return true;
    }

    static void checkDNS(Tins::PDU &pdu) {

        const UDP &udp = pdu.rfind_pdu<UDP>();
        // source and destination port should be equal 53
        if (udp.sport() == 53 || udp.dport() == 53) {
            DNS dns = pdu.rfind_pdu<RawPDU>().to<DNS>();
            for (const auto &query : dns.queries()) {
                std::cout << query.dname() << std::endl;
            }
        }
    }

    static void checkTCP(PDU &pdu) {
        const Tins::IP &ip = pdu.rfind_pdu<Tins::IP>();
        const TCP &tcp = pdu.rfind_pdu<TCP>();
        std::cout << ip.src_addr() << ':' << tcp.sport() << " -> "
                  << ip.dst_addr() << ':' << tcp.dport() << std::endl;
    }
};

UserFacade::UserFacade(char *deviceName) : sniffer(Tins::Sniffer(deviceName)) {
    std::cout << "Sniffing device: " << deviceName << std::endl;
}

#endif //TRAFICANALYZER_USER_FACADE_H
