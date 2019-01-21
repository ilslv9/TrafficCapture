#include <iostream>
#include "user_facade.h"

int main(int argc, char *argv[]) {
    UserFacade *facade = new UserFacade(argv[1]);
    facade->getPacket();
}