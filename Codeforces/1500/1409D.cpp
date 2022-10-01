#include <bits/stdc++.h>

#define FASTIO ios_base::sync_with_stdio(false); cin.tie(0), cout.tie(0)
#define ll long long
using namespace std;
int tab[20];

int main() {
    FASTIO;
    int t, s, n, sum, j;
    cin >> t;
    string temp;
    for (int i = 0; i < t; i++) {
        cin >> temp >> s;
        sum = j = 0;
        for (char x: temp) {
            sum += (x - '0');
            tab[j++] = (x - '0');
        }

        n = temp.length() - 1;
        ll ile = 0, mnoznik = 1;
        while (sum > s && n >= 0) {
            if (n != 0) tab[n - 1]++;
            ile += mnoznik * (10 - tab[n]);
            sum -= (tab[n] - 1);
            mnoznik *= 10;
            n--;
        }
        cout << ile << '\n';
    }

    return 0;
}