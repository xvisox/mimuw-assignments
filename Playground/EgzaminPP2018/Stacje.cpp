#include <bits/stdc++.h>

#define FASTIO ios_base::sync_with_stdio(false); cin.tie(0), cout.tie(0)
using namespace std;

int n, q;

struct Wrap {
    multiset<int, greater<>> dst;
    set<int> s;

    Wrap() {
        s.insert(0);
        s.insert(n);
        dst.insert(n);
    }
};

int lower, upper;
unordered_map<string, struct Wrap> mapka;

void build(int x, string &name) {
    auto &wrap = mapka[name];
    auto &s = wrap.s;
    auto &dst = wrap.dst;

    s.insert(x);
    auto it = s.lower_bound(x);
    lower = *(prev(it));
    upper = *(next(it));

    dst.erase(dst.find(upper - lower));
    dst.insert(upper - x);
    dst.insert(x - lower);
}

void destory(int x) {
    set<int>::iterator it;
    for (auto &[str, wrap]: mapka) {
        auto &s = wrap.s;
        it = s.find(x);
        if (it == s.end()) continue;

        auto &dst = wrap.dst;
        lower = *(prev(it));
        upper = *(next(it));

        dst.erase(dst.find(upper - x));
        dst.erase(dst.find(x - lower));
        dst.insert(upper - lower);
        s.erase(it);
    }
}

bool query(int x, string &s) {
    auto &dst = mapka[s].dst;
    int diff = *dst.begin();
    return x >= diff;
}

int main() {
    FASTIO;
    string s;
    int km, m;
    cin >> n >> q;
    while (q--) {
        cin >> s;
        switch (s[0]) {
            case 'b':
                cin >> km >> m;
                while (m--) {
                    cin >> s;
                    build(km, s);
                }
                break;
            case 'q':
                cin >> km >> s;
                if (query(km, s)) {
                    cout << "TAK\n";
                } else {
                    cout << "NIE\n";
                }
                break;
            case 'd':
                cin >> km;
                destory(km);
                break;
        }
    }


    return 0;
}