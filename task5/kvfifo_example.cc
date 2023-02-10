#include "kvfifo.h"
#include <cassert>
#include <memory>
#include <vector>
#include "kvfifo_test.h"
#include "kwasow.h"
#include "xvisox.h"

int main() {
    mkostyk::mkostyk_kvfifo_test_main();
    xvisox::xvisoxMain();
    kwasow::kwasowMain();
}
