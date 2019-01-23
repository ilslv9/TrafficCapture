//
// Created by ilslv on 23.01.19.
//

#ifndef TRAFICANALYZER_HTTP_HANDLER_H
#define TRAFICANALYZER_HTTP_HANDLER_H

#include <tins/tcp_ip/stream_follower.h>
#include <iostream>
#include <boost/regex.hpp>

using namespace Tins;

class HttpHandler {
public:
    HttpHandler() : request_regex("([\\w]+) ([^ ]+).+\r\nHost: ([\\d\\w\\.-]+)\r\n"),
                    response_regex("HTTP/[^ ]+ ([\\d]+)") {
        folower.new_stream_callback([this](Tins::TCPIP::Stream &stream) {

            stream.client_data_callback([this](Tins::TCPIP::Stream &stream) {
                //Payload should be less then max size from client side
                if (stream.client_payload().size() > MAX_PAYLOAD) {
                    stream.ignore_client_data();
                }
            });

            stream.server_data_callback([this](Tins::TCPIP::Stream &stream) {
                boost::match_results<Tins::TCPIP::Stream::payload_type::const_iterator> client_match;
                boost::match_results<Tins::TCPIP::Stream::payload_type::const_iterator> server_match;
                const Tins::TCPIP::Stream::payload_type &client_payload = stream.client_payload();
                const Tins::TCPIP::Stream::payload_type &server_payload = stream.server_payload();

                bool valid = regex_search(server_payload.begin(), server_payload.end(),
                                          server_match, response_regex) &&
                             regex_search(client_payload.begin(), client_payload.end(),
                                          client_match, request_regex);

                if (valid) {
                    //Execute all properties
                    std::string method = std::string(client_match[1].first, client_match[1].second);
                    std::string url = std::string(client_match[2].first, client_match[2].second);
                    std::string host = std::string(client_match[3].first, client_match[3].second);
                    std::string response_code = std::string(server_match[1].first, server_match[1].second);
                    //Print properties
                    std::cout << method
                              << " http://"
                              << host
                              << url
                              << " -> "
                              << response_code
                              << std::endl;

                    //Ignore first request
                    stream.ignore_client_data();
                    stream.ignore_server_data();
                }

                // If server returns invalid data
                if (stream.server_payload().size() > MAX_PAYLOAD) {
                    stream.ignore_server_data();
                }
            });
        });
    }


    void HttpParsePacket(Tins::PDU &pdu) {
        folower.process_packet(pdu);
    }

    ~HttpHandler() {
        request_regex = nullptr;
        response_regex = nullptr;
    }

private:

    const size_t MAX_PAYLOAD = 3 * 1024;

    boost::regex request_regex{nullptr};

    boost::regex response_regex{nullptr};

    Tins::TCPIP::StreamFollower folower;

};

#endif //TRAFICANALYZER_HTTP_HANDLER_H
