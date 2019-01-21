#ifndef TRAFICANALYZER_USER_FACADE_H
#define TRAFICANALYZER_USER_FACADE_H


#include <pcap.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <iomanip>
#include "../structures.h"

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
        std::cout << "Wait packets..." << std::endl;
//        auto id = pcap_next(handle, &header);

        pcap_loop(handle, -1, captured_packet_callback, nullptr);
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
    static void print_hex_ascii_line(const u_char *payload, int len, int offset) {

        int i;
        int gap;
        const u_char *ch;

        //print offset
        std::cout << std::setw(5) << std::setfill('0') << offset << "   ";

        //print hex
        ch = payload;
        for (i = 0; i < len; i++) {
            std::cout << std::setw(2) << std::setfill('0') << std::hex << static_cast<int>(*ch) << " ";
            ch++;
            if (i == 7)
                std::cout << " ";
        }

        if (len < 8)
            std::cout << " ";

        if (len < 16) {
            gap = 16 - len;
            for (i = 0; i < gap; i++) {
                std::cout << "   ";
            }
        }
        std::cout << "   ";

        //ascii
        ch = payload;
        for (i = 0; i < len; i++) {
            if (isprint(*ch))
                std::cout << *ch;
            else
                std::cout << ".";
            ch++;
        }

        std::cout << std::endl;
    }

    static void print_payload(const u_char *payload, int len) {

        int len_rem = len;
        int line_width = 16;//bytes number in line
        int line_len;
        int offset = 0;//offset counter
        const u_char *ch = payload;

        if (len <= 0)
            return;

        //if data in one line
        if (len <= line_width) {
            print_hex_ascii_line(ch, len, offset);
            return;
        }

        //multiple lines
        for (;;) {
            //line length
            line_len = line_width % len_rem;
            //print line
            print_hex_ascii_line(ch, line_len, offset);
            //total remaining
            len_rem = len_rem - line_len;
            //shift pointer to remaining bytes to print
            ch = ch + line_len;
            //add offset
            offset = offset + line_width;

            if (len_rem <= line_width) {
                //print last line
                print_hex_ascii_line(ch, len_rem, offset);
                break;
            }
        }
    }

    static void captured_packet_callback(u_char *args, const pcap_pkthdr *header, const u_char *packet) {
        static int count = 1;//packet counter

        //packet headers
        const struct sniff_ip *ip;//ip header
        const struct sniff_tcp *tcp;//tcp header
        const char *payload;//payload

        int size_ip;
        int size_tcp;
        int size_payload;

        std::cout << std::endl << "Packet number " << count << ":" << std::endl;
        count++;

        //compute ip header offset
        ip = (struct sniff_ip *) (packet + SIZE_ETHERNET);
        size_ip = IP_HL(ip) * 4;
        if (size_ip < 20) {
            std::cout << "   Invalid ip header length: " << size_ip << " bytes" << std::endl;
            return;
        }

        //Print from to ip addresses
        std::cout << " From: " << inet_ntoa(ip->ip_src) << std::endl;
        std::cout << " To: " << inet_ntoa(ip->ip_dst) << std::endl;
        //Protocol
        switch (ip->ip_p) {
            case IPPROTO_TCP:
                std::cout << " Protocol: TCP" << std::endl;
                break;
            case IPPROTO_UDP:
                std::cout << " Protocol: UDP" << std::endl;
                return;
            case IPPROTO_ICMP:
                std::cout << " Protocol: ICMP" << std::endl;
                return;
            case IPPROTO_IP:
                std::cout << " Protocol: IP" << std::endl;
                return;
            default:
                std::cout << " Protocol: unknown" << std::endl;
                return;
        }

        //compute tcp header offset
        tcp = (struct sniff_tcp *) (packet + SIZE_ETHERNET + size_ip);
        size_tcp = TH_OFF(tcp) * 4;
        if (size_tcp < 20) {
            std::cout << "   Invalid TCP header length: " << size_tcp << " bytes" << std::endl;
            return;
        }

        std::cout << " Src port: " << ntohl(tcp->th_sport) << std::endl;
        std::cout << " Dst port: " << ntohl(tcp->th_dport) << std::endl;

        //compute tcp payload offset
        payload = reinterpret_cast<const char *>((u_char *) (packet + SIZE_ETHERNET + size_ip + size_tcp));

        //compute tcp payload size
        size_payload = ntohs(ip->ip_len) - (size_ip + size_tcp);

        //print payload
        if (size_payload > 0) {
            std::cout << "   Payload (" << size_payload << " bytes):" << std::endl;
            print_payload(reinterpret_cast<const u_char *>(payload), size_payload);
        }
    }
};


#endif //TRAFICANALYZER_USER_FACADE_H
