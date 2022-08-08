#include <bits/stdc++.h>

using namespace std;

#define REP(i, a, b) for (int i = a; i< b; i++)

int main() {
    int w, n;
    cin >> w;
    cin >> n;
    vector<int> ucz(n, 0);
    REP(i, 0, n) cin >> ucz[i];
    sort(ucz.begin(), ucz.end());
    int k = n - 1, p = 0, result = 0;

    while (p < k) {
        if (ucz[p] + ucz[k] <= w) {
            p++;
            k--;
            result++;
        } else {
            k--;
            result++;
        }
    }
    if (k == p && ucz[p] <= w) result++;
    cout << result << '\n';
    return 0;
}