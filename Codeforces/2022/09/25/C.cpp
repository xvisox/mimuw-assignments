#include <bits/stdc++.h>

#define FASTIO ios_base::sync_with_stdio(false); cin.tie(0), cout.tie(0)
#define ll long long
using namespace std;
int odp[11];

int main() {
    FASTIO;
    int t;
    cin >> t;
    for (int k = 0; k < t; k++) {
        string temp;
        cin >> temp;
        for (int &i: odp) {
            i = 0;
        }
        int minTeraz = temp[temp.length() - 1] - '0';
        odp[minTeraz]++;
        int i = temp.length() - 2;
        while (i >= 0) {
            if ((temp[i] - '0') > minTeraz) {
                odp[temp[i] - '0' + 1]++;
            } else {
                minTeraz = temp[i] - '0';
                odp[minTeraz]++;
            }
            i--;
        }
        for (int j = 0; j < 10; j++) {
            for (int dupa = 0; dupa < odp[j]; dupa++) {
                cout << j;
            }
        }
        for (int dupa = 0; dupa < odp[10]; dupa++) {
            cout << 9;
        }
        cout << '\n';
    }
    return 0;
}