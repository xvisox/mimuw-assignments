#include <bits/stdc++.h>

#define ll long long

using namespace std;

ll n, k, lastIdx, result;
int input[500001];
unordered_map<int, int> mapka;

void solve() {
    ll sajz = 0;
    for (ll i = 0; i < n; i++) {
        mapka[input[i]]++;
        if (mapka[input[i]] == 1) sajz++;

        while (sajz > k) {
            mapka[input[lastIdx]]--;
            if (mapka[input[lastIdx]] == 0) {
                sajz--;
            }
            lastIdx++;
        }

        result += (i - lastIdx + 1);
    }
}

int main() {
    cin >> n >> k;
    for (int i = 0; i < n; i++) {
        scanf("%d", &input[i]);
    }

    solve();
    cout << result << endl;
    return 0;
}