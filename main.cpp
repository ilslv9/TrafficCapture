#include <iostream>
#include "traffic_capture.h"

int main(int argc, char *argv[]) {
    Tins::SnifferConfiguration configuration;
    configuration.set_filter("tcp port 80");
    HttpHandler *handler = new HttpHandler();
    UserFacade *facade = new UserFacade(argv[1], handler, configuration);
    facade->getPacket();
}