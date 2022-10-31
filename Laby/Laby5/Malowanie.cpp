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

constexpr int base = 1 << 20;
int t[base << 1], lazy[base << 1];
int n, m;

void push(int v) {
    t[v * 2] += lazy[v] / 2;
    t[v * 2 + 1] += lazy[v] / 2;
    lazy[v * 2] += lazy[v] / 2;
    lazy[v * 2 + 1] += lazy[v] / 2;
    lazy[v] = 0;
}

void update(int v, int tl, int tr, int l, int r, int addend) {
    if (l > r)
        return;
    if (l == tl && tr == r) {
        t[v] = addend * (r - l + 1);
        lazy[v] = addend * (r - l + 1);
    } else {
        push(v);
        int tm = (tl + tr) / 2;
        update(v * 2, tl, tm, l, min(r, tm), addend);
        update(v * 2 + 1, tm + 1, tr, max(l, tm + 1), r, addend);
        t[v] = t[v * 2] + t[v * 2 + 1];
    }
}

int query(int v, int tl, int tr, int l, int r) {
    if (l > r)
        return 0;
    if (l <= tl && tr <= r)
        return t[v];
    push(v);
    int tm = (tl + tr) / 2;
    return query(v * 2, tl, tm, l, min(r, tm)) +
           query(v * 2 + 1, tm + 1, tr, max(l, tm + 1), r);
}

// Chyba działa, ale nie do końca wiem dlaczego.
int main() {
    FASTIO;
    cin >> n >> m;
    int a, b;
    char c;
    // 0 - czarno, 1 - biało
    while (m--) {
        cin >> a >> b >> c;
        update(1, 0, base - 1, a, b, c == 'C' ? 0 : 1);
        cout << query(1, 0, base - 1, 0, base - 1) << endl;
    }

    return 0;
}