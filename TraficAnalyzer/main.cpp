#include <iostream>
#include "user_facade.h"

int main(int argc, char *argv[]) {
//    for (int i = 0; i < argc; i++) {
//        std::cout << "Argument: " << i + " " << argv[i] << std::endl;
//    }
    u_char packet;
    auto *facade = new UserFacade();
    facade->createSession(BUFSIZ, 1, 1000);
    //facade->setFilter();
    packet = facade->getPacket();
    std::cout << packet << std::endl;
}