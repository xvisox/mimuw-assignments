#include <bits/stdc++.h>

#define FASTIO ios_base::sync_with_stdio(false); cin.tie(0), cout.tie(0)
#define ll long long
#define endl '\n'
using namespace std;

constexpr int MAX_N = 500'001;
int n, q;
set<int>::iterator conv[MAX_N]; // indices -> iterator
int which_set[MAX_N]; // indices -> set
set<int> indices[4];

void check() {
    if (indices[1].empty() || indices[2].empty() || indices[3].empty()) {
        cout << "NIE" << endl;
    } else {
        int one_begin = *indices[1].begin();
        int three_end = *indices[3].rbegin();

        int two_begin = *indices[2].begin();
        int two_end = *indices[2].rbegin();

        if (one_begin < two_begin && two_begin < three_end || one_begin < two_end && two_end < three_end) {
            cout << "TAK" << endl;
        } else {
            auto it = indices[2].lower_bound(one_begin);
            if (it != indices[2].end() && *it < three_end) {
                cout << "TAK" << endl;
            } else {
                cout << "NIE" << endl;
            }
        }
    }
}

int main() {
    FASTIO;
    cin >> n;
    int x, y;

    for (int i = 1; i <= n; i++) {
        cin >> x;
        auto it = indices[x].insert(i).first;
        conv[i] = it;
        which_set[i] = x;
    }

    check();

    cin >> q;
    while (q--) {
        cin >> x >> y;

        auto it = conv[x]; // iterator do tego elementu
        indices[which_set[x]].erase(it);

        auto new_it = indices[y].insert(x).first;
        conv[x] = new_it;
        which_set[x] = y;
        check();
    }


    return 0;
}