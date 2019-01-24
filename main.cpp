#include <iostream>
#include "traffic_capture_helper.h"
#include "traffic_capture_helper.h"


int main(int argc, char *argv[]) {
    Tins::SnifferConfiguration configuration;
    std::string port = "";

    //Parse port
    std::string portVal;
    for (int i = 1; i < argc; ++i) {
        if (std::string(argv[i]) == "--port") {
            if (i + 1 < argc) {
                portVal = argv[++i];
                port = "tcp port " + portVal;
            } else {
                port = "";
            }
        }
    }
    //If port is not empty setting filter
    if (!port.empty()) {
        configuration.set_filter(port);
    }

    //Parse device name
    char *deviceName;
    for (int i = 1; i < argc; ++i) {
        if (std::string(argv[i]) == "--device") {
            if (i + 1 < argc) {
                deviceName = argv[++i];
            } else {
                std::cerr << "--device option requires one argument." << std::endl;
                return 1;
            }
        }
    }

    //Parse packets count
    char *packet_count = "";
    for (int i = 1; i < argc; ++i) {
        if (std::string(argv[i]) == "--count") {
            if (i + 1 < argc) {
                packet_count = argv[++i];
            } else {
                packet_count = "";
            }
        }
    }

    int count = 0;

    try {
        std::string temp = packet_count;
        count = std::stoi(temp);
    } catch (std::exception &exception) {
        count = 0;
    }

    HttpHandler *handler = new HttpHandler();
    TrafficCaptureHapler *facade = new TrafficCaptureHapler(deviceName, handler, configuration);
    facade->getPackets(count);
}

