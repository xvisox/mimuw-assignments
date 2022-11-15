#include <bits/stdc++.h>

#define FASTIO ios_base::sync_with_stdio(false); cin.tie(0), cout.tie(0)
#define ll long long
#define ull unsigned long long
#define pll pair<ll, ll>
#define pii pair<int, int>
#define vi vector<int>
#define vii vector<pii>
#define vl vector<ll>
#define vll vector<pll>
#define endl '\n'
using namespace std;

constexpr uint32_t MOD = 1e9;
constexpr uint32_t base = 1 << 15;
uint32_t tree[10][base << 1];
uint32_t n, k;

void add(uint32_t v, uint32_t ile, int nr) {
    v += base;
    tree[nr][v] = ile;
    v /= 2;
    while (v) {
        tree[nr][v] = (tree[nr][2 * v] + tree[nr][2 * v + 1]) % MOD;
        v /= 2;
    }
}

uint32_t query(uint32_t a, uint32_t b, int nr) {
    a += base - 1;
    b += base + 1;
    uint32_t res = 0;
    while ((a / 2) != (b / 2)) {
        if (a % 2 == 0) res = (res + tree[nr][a + 1]) % MOD;
        if (b % 2 == 1) res = (res + tree[nr][b - 1]) % MOD;
        a /= 2;
        b /= 2;
    }
    return res;
}

int main() {
    FASTIO;
    cin >> n >> k;
    uint32_t temp;
    int i = 0;
    while (i < n) {
        cin >> temp;
        temp--;

        add(temp, 1, 0);
        for (int j = 1; j < k; j++) {
            add(temp, query(temp + 1, n - 1, j - 1), j);
        }
        i++;
    }
    cout << tree[k - 1][1] << endl;

    return 0;
}
