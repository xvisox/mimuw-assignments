#include <bits/stdc++.h>

using namespace std;

int n, k;
long long temp, xd;
long long occ[1 << 13];

long long conv(long long bin) {
    long long power = 1;
    long long result = 0;
    while (bin > 0) {
        if (bin % 10 == 1) result += power;
        bin /= 10;
        power *= 2;
    }
    return result;
}

int main() {
    cin >> n;
    cin >> k;
    int size = 1 << k;
    long long res = 0;
    unordered_map<long long, long long> mp;
    for (int i = 0; i < n; i++) {
        cin >> temp;
        if (mp.find(temp) != mp.end()) occ[mp[temp]]++;
        else {
            xd = conv(temp);
            mp[temp] = xd;
            occ[xd]++;
        }
    }
    for (int i = 1; i < size; i++) {
        if (occ[i] == 0) continue;
        res += (occ[i] * (occ[i] - 1)) / 2;
        for (int j = i + 1; j < size; j++) {
            if (occ[j] != 0 && (i & j) != 0) res += occ[i] * occ[j];
        }
    }
    cout << res << '\n';
    return 0;
}
