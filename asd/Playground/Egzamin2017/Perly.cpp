#include <bits/stdc++.h>

#define FASTIO ios_base::sync_with_stdio(false); cin.tie(0), cout.tie(0)
#define ull unsigned long long
#define endl '\n'
using namespace std;

constexpr int MAX_N = 1000001;
ull tab[MAX_N];
ull zero_pod_rzad[MAX_N], jeden_pod_rzad[MAX_N], dwa_pod_rzad[MAX_N];
ull zero_pod_rzad2[MAX_N], jeden_pod_rzad2[MAX_N], dwa_pod_rzad2[MAX_N];

ull max(ull a, ull b, ull c) {
    return max(max(a, b), c);
}

int main() {
    FASTIO;
    int n;
    cin >> n;
    for (int i = 1; i <= n; i++) {
        cin >> tab[i];
    }

    for (int i = 1; i <= n; i++) {
        zero_pod_rzad[i] = max(jeden_pod_rzad[i - 1], dwa_pod_rzad[i - 1], zero_pod_rzad[i - 1]);
        jeden_pod_rzad[i] = zero_pod_rzad[i - 1] + tab[i];
        dwa_pod_rzad[i] = jeden_pod_rzad[i - 1] + tab[i];

        zero_pod_rzad2[i] = max(jeden_pod_rzad2[i - 1], dwa_pod_rzad2[i - 1], zero_pod_rzad2[i - 1]);
        jeden_pod_rzad2[i] = zero_pod_rzad2[i - 1] + tab[i];
        dwa_pod_rzad2[i] = max(jeden_pod_rzad2[i - 1], dwa_pod_rzad[i - 1]) + tab[i];
    }

    ull res = max(zero_pod_rzad[n], max(jeden_pod_rzad[n], dwa_pod_rzad[n]));
    ull res1 = max(zero_pod_rzad2[n], max(jeden_pod_rzad2[n], dwa_pod_rzad2[n]));
    cout << max(res, res1) << endl;

    return 0;
}