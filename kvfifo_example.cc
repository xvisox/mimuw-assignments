#include "kvfifo.h"
#include <cassert>
#include <memory>
#include <vector>
#include "kwasow.h"
#include "xvisox.h"
#include "kvfifo_test.h"

int main() {
    mkostyk::mkostyk_kvfifo_test_main();
    kwasow::kwasowMain();
    xvisox::xvisoxMain();

}
