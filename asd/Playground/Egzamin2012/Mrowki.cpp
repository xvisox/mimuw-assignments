#include <bits/stdc++.h>

#define FASTIO ios_base::sync_with_stdio(false); cin.tie(0), cout.tie(0)
#define endl '\n'
using namespace std;

constexpr int base = 1 << 19;
int t[base << 1];
bool mark[base << 1];
int n, q;

void push(int v) {
    if (mark[v]) {
        mark[v] = false;
        mark[v << 1] = true;
        mark[v << 1 | 1] = true;
        t[v << 1] = t[v << 1 | 1] = 0;
    }
}

void add(int v, int val) {
    v += base;
    t[v] = val;
    v /= 2;
    while (v != 0) {
        t[v] = t[v * 2] + t[v * 2 + 1];
        v /= 2;
    }
}

void update(int d, int val) {
    int v = 1;
    int tl = 0, tr = base - 1, mid;

    while (v != d + base) {
        mid = (tl + tr) / 2;

        push(v);
        if (d <= mid) {
            tr = mid;
            v = v * 2;
        } else {
            tl = mid + 1;
            v = v * 2 + 1;
        }
    }
    t[v] = val;
    v /= 2;
    while (v != 0) {
        t[v] = t[v * 2] + t[v * 2 + 1];
        v /= 2;
    }
}

int find(int v, int tl, int tr, int d) {
    while (v != d + base) {
        int tm = (tl + tr) / 2;

        push(v);
        if (d <= tm) {
            v = v << 1;
            tr = tm;
        } else {
            v = (v << 1) | 1;
            tl = tm + 1;
        }
    }
    return t[v];
}

int query(int v, int tl, int tr, int l, int r, int d, int *res) {
    if (l > r)
        return 0;
    if (l <= tl && tr <= r) {
        if (tl <= d && d <= tr) {
            *res = find(v, tl, tr, d);
        }
        int result = t[v];
        t[v] = 0;
        mark[v] = true; // wszystko poniżej jest zerem
        return result;
    }
    push(v);
    int tm = (tl + tr) / 2;
    int temp = query(v * 2, tl, tm, l, min(r, tm), d, res) +
               query(v * 2 + 1, tm + 1, tr, max(l, tm + 1), r, d, res);
    t[v] -= temp;
    return temp;
}

void read() {
    int x, last = -1, count;
    for (int i = 0; i < n; i++) {
        cin >> x;
        if (x != last) {
            if (last != -1)
                add(last, count);
            last = x;
            count = 1;
        } else
            count++;
    }
    add(last, count);
}

int main() {
    FASTIO;
    cin >> n >> q;

    read();

    int a, b, c, point = -1, range;
    while (q--) {
        cin >> a >> b >> c;
        range = query(1, 0, base - 1, a, b, c, &point);
        cout << range - point << endl;
//        cout << range << ' ' << point << endl;
        update(c, range);
    }

    return 0;
}