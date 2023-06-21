#include <bits/stdc++.h>

#define FASTIO ios_base::sync_with_stdio(false); cin.tie(0), cout.tie(0)
#define ll long long
#define endl '\n'
using namespace std;

ll start, finish, weight;
int n;
constexpr ll base = 1 << 18;
ll tree[base << 1];

void add(ll v, ll value) {
    v += base;
    tree[v] = value;
    v = v >> 1;
    while (v > 0) {
        tree[v] = max(tree[(v << 1)], tree[(v << 1) + 1]);
        v = v >> 1;
    }
}

ll query(ll a, ll b) {
    if (a > b) return 0;

    ll result = 0;
    a += base - 1;
    b += base + 1;
    while (a / 2 != b / 2) {
        if (a % 2 == 0) result = max(tree[a + 1], result);
        if (b % 2 == 1) result = max(tree[b - 1], result);
        a /= 2;
        b /= 2;
    }
    return result;
}

int main() {
    FASTIO;
    vector<tuple<ll, ll, ll>> v;
    cin >> n;
    for (int i = 0; i < n; i++) {
        cin >> start >> finish >> weight;
        v.emplace_back(finish, start, weight);
    }
    sort(v.begin(), v.end());

    int j = 1;
    auto first = v.begin();
    auto firstWeight = get<2>(*first);
    add(j++, firstWeight);
    for (auto it = v.begin() + 1; it != v.end(); it++) {
        tie(finish, start, weight) = *it;

        auto xd = prev(upper_bound(v.begin(), it, make_tuple(start - 1, INT_MAX, INT_MAX)));

        ll tmp = query(0, xd - first + 1) + weight;
        add(j++, tmp);
    }
    cout << query(1, base) << endl;

    return 0;
}