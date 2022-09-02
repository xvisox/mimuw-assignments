#include <bits/stdc++.h>

using namespace std;
set<int> indices[4];
int idxConv[500001];
unordered_set<int> last;

bool check() {
    auto it = indices[1].begin();
    auto end = indices[1].end();
    if (it != end) {
        int idxOne = *it;

        it = lower_bound(indices[2].begin(), indices[2].end(), idxOne);
        end = indices[2].end();

        if (it != end) {
            int idxTwo = *it;

            it = lower_bound(indices[3].begin(), indices[3].end(), idxTwo);
            end = indices[3].end();
            if (it != end) {
                cout << "TAK" << '\n';
                last.insert(idxOne);
                last.insert(idxTwo);
                last.insert(*it);
                return true;
            }
        }
    }
    cout << "NIE" << '\n';
    return false;
}

int main() {
    int n, m;
    cin >> n;

    int temp;
    for (int i = 1; i <= n; i++) {
        scanf("%d", &temp);
        indices[temp].insert(i);
        idxConv[i] = temp;
    }

    check();

    cin >> m;
    int idx, to;
    for (int i = 0; i < m; i++) {
        scanf("%d %d", &idx, &to);
        indices[idxConv[idx]].erase(idx);
        idxConv[idx] = to;
        indices[to].insert(idx);

        if (last.empty() || last.find(idx) != last.end()) {
            if (!check()) {
                last.clear();
            }
        } else {
            cout << "TAK" << '\n';
        }
    }

    return 0;
}