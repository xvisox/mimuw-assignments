#include <bits/stdc++.h>

#define FASTIO ios_base::sync_with_stdio(false); cin.tie(0), cout.tie(0)
#define ll long long
#define ull unsigned long long
#define pll pair<ll, ll>
#define pii pair<int, int>
#define vi vector<int>
#define vii vector<pii>
#define vl vector<ll>
#define vll vector<pll>
#define endl '\n'
using namespace std;

int pattern4[] = {2, 4, 1, 3};
int pattern5[] = {2, 4, 1, 3, 5};
int pattern6[] = {1, 4, 6, 2, 5, 3};
int pattern7[] = {1, 4, 7, 3, 6, 2, 5};

void construct(int n) {
    if (n < 4) {
        cout << -1 << endl;
        return;
    }
    int ile = n / 4 - 1;

    int j = 0;
    while (j < ile) {
        for (int i: pattern4) cout << i + 4 * j << ' ';
        j++;
    }

    if (n % 4 == 1) {
        for (int i: pattern5) cout << i + 4 * j << ' ';
    } else if (n % 4 == 2) {
        for (int i: pattern6) cout << i + 4 * j << ' ';
    } else if (n % 4 == 3) {
        for (int i: pattern7) cout << i + 4 * j << ' ';
    } else {
        for (int i: pattern4) cout << i + 4 * j << ' ';
    }

    cout << endl;
}

int main() {
    FASTIO;
    int t;
    cin >> t;
    while (t--) {
        int n;
        cin >> n;
        construct(n);
    }


    return 0;
}