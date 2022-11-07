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

string tmp;
int t, n;

int count(int l, int r, char x) {
    int counter = 0;
    for (int i = l; i <= r; i++) {
        if (tmp[i] != x) counter++;
    }
    return counter;
}

int search(char x, int l, int r) {
    if (l == r) {
        return tmp[l] == x ? 0 : 1;
    } else {
        char next = x;
        next++;

        int mid = (l + r) / 2, left, right;
        left = count(l, mid, x);
        right = count(mid + 1, r, x);

        if (mid + 1 <= r) {
            left += search(next, mid + 1, r);
        }
        if (l <= mid) {
            right += search(next, l, mid);
        }
        return min(left, right);
    }
}

int main() {
    FASTIO;
    cin >> t;
    while (t--) {
        cin >> n;
        cin >> tmp; // 0...n-1
        cout << search('a', 0, n - 1) << endl;
    }


    return 0;
}