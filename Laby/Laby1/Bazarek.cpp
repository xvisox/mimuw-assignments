#include <bits/stdc++.h>

#define FASTIO ios_base::sync_with_stdio(false); cin.tie(0), cout.tie(0)
#define ll long long
#define pll pair<ll, ll>
#define pii pair<int, int>
#define vi vector<int>
#define vii vector<pii>
#define vl vector<ll>
#define vll vector<pll>
#define endl '\n'
using namespace std;
int n, m;
constexpr int MAX_N = 1e6 + 7;
ll koszt[MAX_N], odp[MAX_N], even[MAX_N], odd[MAX_N];

int main() {
    FASTIO;
    cin >> n;
    for (int j = 0; j < n; j++) {
        cin >> koszt[n - j];
    }
    for (int j = n; j > 0; j--) {
        if (koszt[j] % 2 == 0) {
            even[j] = koszt[j];
            odd[j] = odd[j + 1];
        } else {
            odd[j] = koszt[j];
            even[j] = even[j + 1];
        }
    }

    ll sum = 0, lastOdd = 0, lastEven = 0;
    for (int i = 1; i <= n; i++) {
        sum += koszt[i];
        if (koszt[i] % 2 == 0) {
            lastEven = koszt[i];
        } else {
            lastOdd = koszt[i];
        }

        if (sum % 2 == 1) {
            odp[i] = sum;
        } else {
            ll nowaOdp = -1;
            if (lastOdd && even[i + 1]) {
                nowaOdp = sum - lastOdd + even[i + 1];
            }
            if (lastEven && odd[i + 1]) {
                nowaOdp = max(nowaOdp, sum - lastEven + odd[i + 1]);
            }
            odp[i] = nowaOdp;
        }
    }

    int temp;
    cin >> m;
    while (m--) {
        cin >> temp;
        cout << odp[temp] << endl;
    }

    return 0;
}