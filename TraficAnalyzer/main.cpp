#include <iostream>
#include "pcap.h"
#include "facades/user_facade.h"

int main(int argc, char *argv[]) {
    auto *facade = new user_facade();
    facade->createSession(BUFSIZ, 1, 1000);
}