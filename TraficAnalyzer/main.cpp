#include <iostream>
#include "user_facade.h"

int main(int argc, char *argv[]) {
    auto *facade = new UserFacade();
    facade->createSession(BUFSIZ, 1, 1000);
}