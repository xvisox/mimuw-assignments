#include <bits/stdc++.h>

#define FASTIO ios_base::sync_with_stdio(false); cin.tie(0), cout.tie(0)
#define ll long long
using namespace std;

int main() {
    FASTIO;
    string temp;
    cin >> temp;
    bool isAB = false, isBA = false;
    int n = temp.length();
    int firstAB, firstBA;
    for (int i = 1; i < n && (!isBA || !isAB); i++) {
        if (!isAB && temp[i - 1] == 'A' && temp[i] == 'B') {
            firstAB = i;
            isAB = true;
        } else if (!isBA && temp[i - 1] == 'B' && temp[i] == 'A') {
            firstBA = i;
            isBA = true;
        }
    }
    if (!isAB || !isBA) {
        cout << "NO\n";
        return 0;
    }
    isAB = isBA = false;
    int lastAB, lastBA;
    for (int i = n - 1; i > 0 && (!isBA || !isAB); i--) {
        if (!isAB && temp[i - 1] == 'A' && temp[i] == 'B') {
            lastAB = i;
            isAB = true;
        } else if (!isBA && temp[i - 1] == 'B' && temp[i] == 'A') {
            lastBA = i;
            isBA = true;
        }
    }
    if (abs(lastAB - firstBA) > 1 || abs(lastBA - firstAB) > 1) {
        cout << "YES\n";
    } else cout << "NO\n";

    return 0;
}