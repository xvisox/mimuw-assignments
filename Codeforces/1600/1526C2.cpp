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
ll n;

int main() {
    FASTIO;
    priority_queue<ll, vector<ll>, greater<>> pq;
    cin >> n;
    ll temp, res = 0;
    ll sum = 0;
    while (n--) {
        cin >> temp;
        if (sum + temp >= 0) {
            sum += temp;
            res++;

            if (temp < 0) {
                pq.push(temp);
            }
        } else {
            if (!pq.empty() && pq.top() < temp) {
                sum -= pq.top();
                sum += temp;
                pq.pop();
                pq.push(temp);
            }
        }
    }
    cout << res << endl;

    return 0;
}