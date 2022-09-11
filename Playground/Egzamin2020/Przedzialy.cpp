#include <bits/stdc++.h>

using namespace std;

int n, m;

set<int> koniec; // uporzadkowany od najmniejszych do najwiekszych
set<int, greater<>> poczatek; // uporzadkowany od najwiekszych do najmniejszych

int main() {
    cin >> n >> m;

    char c;
    int ai, bi;
    int result;
    for (int i = 0; i < m; i++) {
        scanf("\n%c %d %d", &c, &ai, &bi);
        if (c == '+') {
            if (ai == 1) {
                poczatek.insert(bi);
            } else {
                koniec.insert(ai);
            }
        } else {
            if (ai == 1) {
                poczatek.erase(bi);
            } else {
                koniec.erase(ai);
            }
        }

        if (!poczatek.empty()) {
            result = n - *poczatek.begin();
        } else {
            result = n;
        }
        if (!koniec.empty()) {
            result -= (n - *koniec.begin() + 1);
        }
        cout << max(result, 0) << '\n';
    }

    return 0;
}