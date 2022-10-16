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
ull k;

ull binpow(ull a, ull b) {
    if (b == 0)
        return 1;
    ull res = binpow(a, b / 2);
    if (b % 2)
        return res * res * a;
    else
        return res * res;
}

bool check(ull mid) {
    return binpow(mid, 10) >= k;
}

int main() {
    FASTIO;
    cin >> k;
    if (k == 1) {
        cout << "codeforces\n";
        return 0;
    }

    ull l = 1, p = 100, mid;
    while (l < p) {
        mid = (l + p) / 2;
        if (!check(mid)) {
            l = mid + 1;
        } else {
            p = mid;
        }
    }
    l--;
    vector<ull> res(10, l);
    ull result = binpow(l, 10);
    int i = 0;
    while (result < k) {
        result /= l;
        result *= (l + 1);
        res[i++] = l + 1;
    }
    i = 0;
    char arr[] = {'c', 'o', 'd', 'e', 'f', 'o', 'r', 'c', 'e', 's'};
    for (char x: arr) {
        int j = 0;
        while (j < res[i]) {
            cout << x;
            j++;
        }
        i++;
    }
    cout << endl;

    return 0;
}