#include <bits/stdc++.h>

#define FASTIO ios_base::sync_with_stdio(false); cin.tie(0), cout.tie(0)
#define ul unsigned long long
#define endl '\n'
using namespace std;

constexpr int MAX_N = 500'001;
int n, m;
unordered_map<ul, ul> edges[MAX_N]; // weight -> count
ul ile[MAX_N];

int main() {
    FASTIO;
    cin >> n >> m;
    ul ai, bi, wi;
    for (int i = 0; i < m; ++i) {
        cin >> ai >> bi >> wi;
        edges[ai][wi]++;
        edges[bi][wi]++;
        ile[ai]++;
        ile[bi]++;
    }

    ul count = 0;
    for (int i = 1; i <= n; i++) {
        count += ile[i] * (ile[i] - 1) / 2;
        for (auto &e: edges[i]) {
            count -= e.second * (e.second - 1) / 2;
        }
    }
    cout << count << endl;

//    int xd = 124999124878;

    return 0;
}