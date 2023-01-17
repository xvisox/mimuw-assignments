#include <bits/stdc++.h>

using namespace std;

#define endl '\n'

int n, m;
multiset<int, greater<>> dst;
set<int> s;

int main() {
    cin >> n >> m;

    s.insert(0);
    s.insert(n);
    dst.insert(n);

    int x, lower, upper;
    while (m--) {
        cin >> x;
        if (s.find(x) != s.end()) {
            cout << *dst.begin() << endl;
            continue;
        }

        s.insert(x);
        auto it = s.lower_bound(x);
        lower = *(prev(it));
        upper = *(next(it));

        dst.erase(dst.find(upper - lower));
        dst.insert(upper - x);
        dst.insert(x - lower);

        cout << *dst.begin() << endl;
    }

    return 0;
}