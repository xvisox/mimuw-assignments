#include <bits/stdc++.h>

#define FASTIO ios_base::sync_with_stdio(false); cin.tie(0), cout.tie(0)
#define ll long long
#define endl '\n'
using namespace std;

map<int, int> m;
int n, q;
vector<int> queries;

void read() {
    cin >> n;
    int aux;
    for (int i = 0; i < n; ++i) {
        cin >> aux;
        m[aux]++;
    }
    cin >> q;
    while (q--) {
        cin >> aux;
        queries.push_back(aux);
    }
}

int main() {
    FASTIO;
    read();

    for (auto &i: queries) {
        for (int j = 0; j < i; j++) {
            auto zetony = m.rbegin()->second;
            auto val = m.rbegin()->first;

            int ile = min(zetony, i - j);
            zetony -= ile;
            if (zetony == 0) {
                m.erase(m.rbegin()->first);
            } else {
                m.rbegin()->second = zetony;
            }

            m[val / 2] += ile;
            m[(val + 1) / 2] += ile;
            j += ile - 1;
        }
        cout << m.size() << endl;
    }


    return 0;
}