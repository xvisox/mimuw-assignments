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

int arr[8001];

int main() {
    FASTIO;
    int t, n, res;
    cin >> t;
    for (int test = 0; test < t; test++) {
        cin >> n;
        for (int i = 0; i < n; i++) {
            cin >> arr[i];
        }
        if (n == 1) {
            cout << 0 << endl;
            continue;
        }

        res = 0;
        for (int j = 0; j < n; j++) {
            int l = 0, r = 1, sum = arr[0] + arr[1], expect = arr[j];
            while (r < n && sum != expect) {
                if (sum > expect && (r - l) > 1) {
                    sum -= arr[l++];
                } else {
                    sum += arr[++r];
                }
            }
            if (sum == expect && r < n) {
                res++;
            }
        }
        cout << res << endl;
    }

    return 0;
}