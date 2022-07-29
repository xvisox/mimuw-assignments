#include<bits/stdc++.h>

#define RAND '%'
using namespace std;

// To zadanie jeszcze do ogarnięcia:
// Dlaczego i < between?
// Złożoność:
// 1) Czas O(n))
// 2) Pamięć O(1)
int main() {
    string pattern;
    cin >> pattern;
    int len = pattern.size();
    int between = len - 1, lastIdx;
    char lastChar = RAND;

    for (int i = 0; i < between; i++) {
        if (pattern[i] != '*') {
            if (lastChar != pattern[i]) {
                between = min(i - lastIdx - 1, between);
            }
            lastChar = pattern[i];
            lastIdx = i;
        }
    }

    cout << len - between;
    return 0;
}