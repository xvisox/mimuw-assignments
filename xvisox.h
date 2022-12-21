#ifndef XVISOX_H_
#define XVISOX_H_

#define INF 9999
#define ELEMENTS 5

#include "kvfifo.h"
#include <cassert>
#include <iostream>

namespace xvisox {

    void testPush();

    void testCopy();

    void testFront();

    void testMoveToBack();

    void testFailedCopy();

    void testConstructor();

    void xvisoxMain() {
        std::cout << "Starting xvisox tests" << std::endl;
        testPush();
        testFront();
        testCopy();
        testMoveToBack();
        testFailedCopy();
        testConstructor();
        std::cout << "All tests passed" << std::endl;

    }

    int throwCounter;

    void ThisCanThrow() {
        throwCounter--;
        if (throwCounter == 0)
            throw std::runtime_error("ThisCanThrow");
    }

    struct TestClass {
        TestClass(int v = 0) {
            ThisCanThrow();
            p = new int(v);
        }

        TestClass(const TestClass &rhs) {
            ThisCanThrow();
            p = new int(*rhs.p);
        }

        TestClass &operator=(const TestClass &rhs) {
            if (this != &rhs) {
                ThisCanThrow();
                delete p;
                p = new int(*rhs.p);
            }
            return *this;
        }

        bool operator==(const TestClass &rhs) const {
            ThisCanThrow();
            return *p == *rhs.p;
        }

        std::strong_ordering operator<=>(const TestClass &rhs) const {
            ThisCanThrow();
            return *p <=> *rhs.p;
        }

        ~TestClass() {
            delete p;
        }

        int *p;
    };

    void testPush() {
        std::cout << "Starting test push" << std::endl;
        kvfifo<TestClass, TestClass> kvf;
        bool success = false;
        for (int nextThrowCount = 1; !success; ++nextThrowCount) {
            kvfifo<TestClass, TestClass> dup = kvf;

            try {
                throwCounter = nextThrowCount;
                auto t1 = TestClass(1);
                auto t2 = TestClass(2);
                dup.push(t1, t2);
                success = true;

                throwCounter = INF;
                assert(dup.size() == 1);
                assert(dup.count(TestClass(1)) == 1);
                assert(dup.front().first == TestClass(1));
                assert(dup.front().second == TestClass(2));
            } catch (...) {
                assert(kvf == dup);
                std::cout << "testPush: " << nextThrowCount << " throws" << std::endl;
            }
        }
    }

    void testFront() {
        std::cout << "Starting test front" << std::endl;
        kvfifo<TestClass, TestClass> kvf;
        bool success = false;

        throwCounter = INF;
        auto t1 = TestClass(1);
        auto t2 = TestClass(2);
        kvf.push(t1, t2);

        for (int nextThrowCount = 1; !success; ++nextThrowCount) {
            kvfifo<TestClass, TestClass> dup = kvf;

            try {
                throwCounter = nextThrowCount;
                auto res = dup.front();

                throwCounter = INF;
                assert(res.first == TestClass(1));
                assert(res.second == TestClass(2));
                assert(dup.size() == 1);
                success = true;
            } catch (...) {
                assert(kvf == dup);
                std::cout << "testFront: " << nextThrowCount << " throws" << std::endl;
            }
        }
    }

    void testCopy() {
        std::cout << "Starting test copy" << std::endl;
        std::cerr << "WITHOUT VALGRIND THIS TEST WON'T TELL ANYTHING ABOUT MEMORY LEAKS!" << std::endl;
        kvfifo<TestClass, TestClass> kvf;
        bool success = false;

        throwCounter = INF;
        int elements = ELEMENTS * 2;
        for (int i = 0; i < ELEMENTS; ++i) {
            auto t1 = TestClass(i);
            auto t2 = TestClass(i + ELEMENTS);
            kvf.push(t1, t1);
            kvf.push(t1, t2);
        }

        for (int nextThrowCount = 1; !success; ++nextThrowCount) {
            auto &ref = kvf.front().first;

            try {
                throwCounter = nextThrowCount;
                kvfifo<TestClass, TestClass> copy(kvf);

                throwCounter = INF;
                assert(copy.size() == elements);
                success = true;
            } catch (...) {
                std::cout << "testCopy: " << nextThrowCount << " throws" << std::endl;
            }
        }
    }

    void testMoveToBack() {
        std::cout << "Starting test move_to_back" << std::endl;
        kvfifo<TestClass, TestClass> kvf;
        bool success = false;

        throwCounter = INF * 69;
        int elements = ELEMENTS * 2;
        std::vector<TestClass> res_keys, res_values;
        for (int i = 0; i < ELEMENTS; ++i) {
            auto t1 = TestClass(i);
            auto t2 = TestClass(i + ELEMENTS);
            kvf.push(t1, t1);
            kvf.push(t1, t2);
            if (kvf.size() > 4) {
                res_keys.push_back(t1);
                res_values.push_back(t1);
                res_keys.push_back(t1);
                res_values.push_back(t2);
            }
        }

        res_keys.emplace_back(1);
        res_keys.emplace_back(1);
        res_keys.emplace_back(0);
        res_keys.emplace_back(0);
        res_values.emplace_back(1);
        res_values.emplace_back(6);
        res_values.emplace_back(0);
        res_values.emplace_back(5);

        // 0 0 1 1 2 2 3 3 4 4
        // 0 5 1 6 2 7 3 8 4 9
        // ->
        // 1 1 2 2 3 3 4 4 0 0
        // 1 6 2 7 3 8 4 9 0 5
        // ->
        // 2 2 3 3 4 4 0 0 1 1
        // 2 7 3 8 4 9 0 5 1 6
        // ->
        // 2 2 3 3 4 4 1 1 0 0
        // 2 7 3 8 4 9 1 6 0 5

        for (int nextThrowCount = 1; !success; ++nextThrowCount) {
            kvfifo<TestClass, TestClass> dup = kvf;

            try {
                throwCounter = nextThrowCount;
                dup.move_to_back(TestClass(0));
                dup.move_to_back(TestClass(1));
                dup.move_to_back(TestClass(0));

                throwCounter = INF * 69;
                int j = 0;
                while (!dup.empty()) {
                    auto res = dup.front();
                    assert(res.first == res_keys[j]);
                    assert(res.second == res_values[j]);
                    dup.pop();
                    j++;
                }
                success = true;
            } catch (...) {
                std::cout << "testMoveToBack: " << nextThrowCount << " throws" << std::endl;
            }
        }
    }

    void testFailedCopy() {
        std::cout << "Starting test failed copy" << std::endl;
        kvfifo<TestClass, TestClass> kvf;
        kvfifo<TestClass, TestClass> empty_kvf;
        bool success = false;
        throwCounter = INF;
        int elements = ELEMENTS;
        for (int i = 0; i < ELEMENTS; ++i) {
            auto t1 = TestClass(i);
            kvf.push(t1, t1);
        }

        auto &ref = kvf.front().first;
        for (int nextThrowCount = 1; !success; ++nextThrowCount) {
            kvfifo<TestClass, TestClass> dup = empty_kvf;

            try {
                throwCounter = nextThrowCount;
                empty_kvf = kvf;

                throwCounter = INF * 69;
                assert(empty_kvf.size() == elements);
                success = true;
            } catch (...) {
                assert(empty_kvf == dup);
                std::cout << "testFailedCopy: " << nextThrowCount << " throws" << std::endl;
            }
        }
    }

    void testConstructor() {
        kvfifo<TestClass, TestClass> kvf;
        kvfifo<TestClass, TestClass> kvf2;
        kvf = kvf2;
    }
}

#endif /* XVISOX_H_ */