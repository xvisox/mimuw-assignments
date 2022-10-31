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

constexpr ll MOD = 1e9 + 7;
constexpr ll base = 1 << 19;
ll n, k, l;
ll tree[base << 1][2];
vl v;

ll ll_min(ll a, ll b) {
    return a < b ? a : b;
}

void add(ll a, ll mini, ll ile) {
    a += base;
    tree[a][0] = mini;
    tree[a][1] = ile;
    a /= 2;
    while (a != 0) {
        tree[a][0] = ll_min(tree[2 * a][0], tree[2 * a + 1][0]);
        tree[a][1] = 0;
        if (tree[2 * a][0] == tree[a][0]) tree[a][1] = (tree[a][1] + tree[2 * a][1]) % MOD;
        if (tree[2 * a + 1][0] == tree[a][0]) tree[a][1] = (tree[a][1] + tree[2 * a + 1][1]) % MOD;
        a /= 2;
    }
}

pll query(ll a, ll b) {
    a += base - 1;
    b += base + 1;
    vl res(2);
    res[0] = LLONG_MAX;
    res[1] = 0;
    while ((a / 2) != (b / 2)) {
        if (a % 2 == 0) {
            if (res[0] > tree[a + 1][0]) {
                res[0] = tree[a + 1][0];
                res[1] = tree[a + 1][1];
            } else if (res[0] == tree[a + 1][0]) {
                res[1] = (res[1] + tree[a + 1][1]) % MOD;
            }
        }
        if (b % 2 == 1) {
            if (res[0] > tree[b - 1][0]) {
                res[0] = tree[b - 1][0];
                res[1] = tree[b - 1][1];
            } else if (res[0] == tree[b - 1][0]) {
                res[1] = (res[1] + tree[b - 1][1]) % MOD;
            }
        }
        a /= 2;
        b /= 2;
    }
    return {res[0], res[1]};
}

void read() {
    FASTIO;
    cin >> n >> k >> l;
    ll temp;
    for (int i = 0; i < n; i++) {
        cin >> temp;
        v.push_back(temp);
    }
    sort(v.begin(), v.end());
}

void print() {
//    for (ll j = base; j < base + n; j++) {
//        cout << v[j - base] << ' ' << tree[j][0] << ' ' << tree[j][1] << endl;
//    }
//    cout << endl;
    ll resMin = LLONG_MAX, resIle = 0;
    ll bound = v[n - 1] - k, j = 0;
    while (v[n - 1 - j] >= bound && j < n) {
        if (resMin > tree[base + n - 1 - j][0]) {
            resMin = tree[base + n - 1 - j][0];
            resIle = tree[base + n - 1 - j][1];
        } else if (resMin == tree[base + n - 1 - j][0]) {
            resIle = (resIle + tree[base + n - 1 - j][1]) % MOD;
        }
        j++;
    }

    cout << resMin << ' ' << resIle << endl;
}

int main() {
    read();
    ll i = 0;
    ll firstVal = *v.begin();
    const auto first = v.begin();

    for (auto it = v.begin(); it != v.end(); it++) {
        if (firstVal >= (*it - k) || it == first) {
            add(i, 1, 1);
        } else {
            auto upr = upper_bound(first, it, v[i] - l);
            auto lwr = lower_bound(first, it, v[i] - k);

            if (upr != first)
                upr--;

            if (lwr != first) {
                lwr--;
            }

            if (lwr != first) {
                lwr = lower_bound(first, it, *lwr - k);
            }

            ll mini, ile, pocz = lwr - first, kon = upr - first;
            if (pocz > kon) swap(pocz, kon);

            if (v[kon] > v[i] - l) {
                add(i, MOD, 0);
                i++;
                continue;
            }

            tie(mini, ile) = query(pocz, kon);
            add(i, mini + 1, ile);
        }
        i++;
    }

    print();
    return 0;
}
