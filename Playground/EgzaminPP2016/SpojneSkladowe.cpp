#include <bits/stdc++.h>

#define FASTIO ios_base::sync_with_stdio(false); cin.tie(0), cout.tie(0)
#define ul unsigned long long
#define endl '\n'
using namespace std;

ul n, ai, res;
set<ul> v;
stack<set<ul>::iterator> s;

int main() {
    FASTIO;
    cin >> n;
    for (ul i = 0; i < n; ++i) {
        cin >> ai;
        if (ai == 0) {
            res++;
            continue;
        }

        for (auto it = v.begin(); it != v.end(); ++it) {
            if ((ai & (*it)) > 0) {
                ai |= (*it);
                s.push(it);
            }
        }

        while (!s.empty()) {
            v.erase(s.top());
            s.pop();
        }

        v.insert(ai);
    }
    cout << v.size() + res << endl;

    return 0;
}