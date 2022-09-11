#include <bits/stdc++.h>

#define ll long long

using namespace std;

int n;
vector<ll> tab;

void read() {
    ll temp;
    cin >> n;
    for (int i = 0; i < n; i++) {
        scanf("%lld", &temp);
        tab.push_back(temp);
    }
    sort(tab.begin(), tab.end());
}

void solve() {
    int result = 0;
    int temp = 1;
    ll last = tab[0];
    for (int i = 1; i < n; i++) {
        if (tab[i] - last <= 1) {
            temp++;
        } else {
            result = max(result, temp);
            temp = 1;
        }
        last = tab[i];
    }
    result = max(result, temp);
    cout << result << endl;
}

int main() {
    read();
    solve();
    return 0;
}