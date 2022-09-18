#include <bits/stdc++.h>

using namespace std;
int n, maks = INT_MAX, temp;
map<int, int> mapka;
int cost[10];

void read() {
    cin >> n;
    for (int i = 1; i <= 9; i++) {
        scanf("%d", &temp);
        maks = min(maks, temp);
        cost[i] = temp;
        mapka[temp] = max(i, mapka[temp]);
    }
}

int main() {
    read();

    if (maks > n) {
        cout << -1 << endl;
    } else {
        int maxLength = 0, minVal = INT_MAX, length;
        for (auto [w, val]: mapka) {
            length = n / w;
            if (length < maxLength) {
                break;
            }
            maxLength = max(maxLength, length);
            minVal = min(minVal, val);
        }

        n -= (cost[minVal] * maxLength);
        int i = 9, diff;
        while (i > minVal && maxLength > 0) {
            diff = cost[i] - cost[minVal];
            length = n / diff;
            n -= (length * diff);
            maxLength -= length;

            if (maxLength < 0) length += maxLength;
            for (int j = 0; j < length; j++) {
                printf("%d", i);
            }
            i--;
        }
        for (int j = 0; j < maxLength; j++) {
            printf("%d", minVal);
        }
    }

    return 0;
}