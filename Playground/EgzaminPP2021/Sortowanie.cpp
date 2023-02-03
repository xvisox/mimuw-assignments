#include <bits/stdc++.h>

#define FASTIO ios_base::sync_with_stdio(false); cin.tie(0), cout.tie(0)
#define ll long long
#define endl '\n'
using namespace std;

constexpr int base = 1 << 18;
int t[base << 1], lazy[base << 1];

void push(int v) {
    if (lazy[v] == 0) return;

    if (lazy[v] > 0) {
        t[v * 2] = lazy[v] / 2;
        t[v * 2 + 1] = lazy[v] / 2;
        lazy[v * 2] = lazy[v] / 2;
        lazy[v * 2 + 1] = lazy[v] / 2;
    } else {
        t[v * 2] = 0;
        t[v * 2 + 1] = 0;
        lazy[v * 2] = -1;
        lazy[v * 2 + 1] = -1;
    }
    lazy[v] = 0;
}

void update(int v, int tl, int tr, int l, int r, int addend) {
    if (l > r)
        return;
    if (l == tl && tr == r) {
        t[v] = addend * (r - l + 1);
        lazy[v] = addend > 0 ? addend * (r - l + 1) : -1;
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

int n, m;

int main() {
    FASTIO;
    cin >> n >> m;
    string s;
    cin >> s;
    int i = 1;
    for (char c: s) {
        update(1, 0, base - 1, i, i, c != '0');
        i++;
    }
    char c;
    int ai, bi;
    while (m--) {
        cin >> c;
        if (c == '?') {
            cin >> ai;
            cout << query(1, 0, base - 1, ai, ai) << endl;
        } else if (c == '<') {
            cin >> ai >> bi;
            int ile = query(1, 0, base - 1, ai, bi);
            if (ile == 0 || ile == (bi - ai + 1)) continue;

            update(1, 0, base - 1, ai, bi - ile, 0);
            update(1, 0, base - 1, bi - ile + 1, bi, 1);
        } else {
            cin >> ai >> bi;
            int ile = query(1, 0, base - 1, ai, bi);
            if (ile == 0 || ile == (bi - ai + 1)) continue;

            update(1, 0, base - 1, ai, ai + ile - 1, 1);
            update(1, 0, base - 1, ai + ile, bi, 0);
        }
    }

    return 0;
}