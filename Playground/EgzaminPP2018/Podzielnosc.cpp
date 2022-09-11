#include <bits/stdc++.h>

#define TAK "TAK\n"
#define NIE "NIE\n"
#define ll long long
#define MAX_N 100'001
#define MAX_M 200'001

using namespace std;
int n, m;
int tab[MAX_N], odp[MAX_N];
int ans[MAX_M];
unordered_map<int, set<pair<int, int>, greater<>>> dupa;

void query(int l, int r) {
    int result = 0;
    int jedynki, dwojki, zera;
    zera = jedynki = dwojki = 0;
    for (int i = l; i <= r; i++) {
        if (tab[i] == 0) {
            zera++;
        } else if (tab[i] == 1) {
            swap(zera, jedynki);
            swap(zera, dwojki);
            jedynki++;
        } else {
            swap(zera, jedynki);
            swap(jedynki, dwojki);
            dwojki++;
        }
        result += zera;
        odp[i] = result;
    }
}

void read() {
    cin >> n >> m;
    ll temp;
    for (int i = 1; i <= n; i++) {
        scanf("%lld", &temp);
        tab[i] = (temp % 3);
    }
    int ai, bi;
    for (int i = 0; i < m; i++) {
        scanf("%d %d", &ai, &bi);
        dupa[ai].insert({bi, i});
    }
}

int main() {
    read();
    int l, r, idx;
    for (const auto &el: dupa) {
        l = el.first;
        r = (*el.second.begin()).first;
        query(l, r);
        for (auto k: el.second) {
            ans[k.second] = odp[k.first];
        }
    }
    for (int i = 0; i < m; i++) {
        cout << ans[i] << '\n';
    }
    return 0;
}