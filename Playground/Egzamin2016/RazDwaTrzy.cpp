#include <bits/stdc++.h>

#define MAX_N 500'001

using namespace std;
set<int> indices[4];
int conv[MAX_N];
bool last;
unordered_set<int> odp;

void tak() {
    cout << "TAK\n";
    last = true;
}

void nie() {
    cout << "NIE\n";
    last = false;
}

void check() {
    odp.clear();
    if (indices[1].size() && indices[2].size() && indices[3].size()) {
        int one_begin = *indices[1].begin();
        int three_end = *indices[3].rbegin();
        int two_begin = *indices[2].begin();
        int two_end = *indices[2].rbegin();

        if (one_begin < two_begin && two_begin < three_end) {
            tak();
            odp.insert(one_begin);
            odp.insert(two_begin);
            odp.insert(three_end);
        } else if (one_begin < two_end && two_end < three_end) {
            tak();
            odp.insert(one_begin);
            odp.insert(two_end);
            odp.insert(three_end);
        } else {
            auto it = upper_bound(indices[2].begin(), indices[2].end(), one_begin);
            if (it != indices[2].end() && *it < three_end) {
                tak();
                odp.insert(one_begin);
                odp.insert(*it);
                odp.insert(three_end);
            } else {
                nie();
            }
        }
    } else {
        nie();
    }
}

int main() {
    int n, m;
    cin >> n;

    int temp;
    for (int i = 1; i <= n; i++) {
        scanf("%d", &temp);
        indices[temp].insert(i);
        conv[i] = temp;
    }
    check();

    cin >> m;
    int idx, to;
    for (int i = 0; i < m; i++) {
        scanf("%d %d", &idx, &to);
        if (conv[idx] == to) {
            if (last) tak();
            else nie();
            continue;
        }

        indices[conv[idx]].erase(idx);
        conv[idx] = to;
        indices[to].insert(idx);
        if (!odp.empty() && odp.find(idx) == odp.end()) {
            if (last) tak();
            else nie();
        } else check();
    }

    return 0;
}