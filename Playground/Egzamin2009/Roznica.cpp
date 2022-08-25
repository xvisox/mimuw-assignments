#include <bits/stdc++.h>

#define ll long long

using namespace std;

ll n, k, temp;
unordered_set<ll> secik;

int main() {
    cin >> n >> k;

    for (int i = 0; i < n; i++) {
        scanf("%lld", &temp);
        if (secik.find(temp + k) != secik.end()) {
            cout << temp + k << ' ' << temp << endl;
            return 0;
        }
        if (secik.find(temp - k) != secik.end()) {
            cout << temp << ' ' << temp - k << endl;
            return 0;
        }

        secik.insert(temp);
    }

    cout << "NIE" << endl;
    return 0;
}