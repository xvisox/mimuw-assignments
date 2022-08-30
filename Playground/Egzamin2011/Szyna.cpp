#include <bits/stdc++.h>

#define ll long long
#define MAX_N 500001

using namespace std;

unordered_set<ll> secik;

int main() {
    int n;
    cin >> n;

    ll temp, result = 0;
    for (int i = 0; i < n; i++) {
        scanf("%lld", &temp);
        if (secik.find(temp) == secik.end()) {
            secik.insert(temp);
        } else {
            result++;
            secik.clear();
        }
    }
    cout << result << endl;
    return 0;
}