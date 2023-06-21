#include <bits/stdc++.h>

using namespace std;

int n, temp, bits;
unordered_set<int> mask;

void handle(int co) {
    if (mask.find(co) != mask.end()) {
        mask.erase(co);
        bits--;

        if (co != 0) handle(co + 1);
        else handle(1);
    } else {
        mask.insert(co);
        bits++;
    }
}

int main() {
    cin >> n;

    for (int i = 0; i < n; i++) {
        scanf("%d", &temp);
        handle(temp);
        printf("%d\n", bits);
    }

    return 0;
}