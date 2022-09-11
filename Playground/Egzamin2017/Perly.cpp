#include <bits/stdc++.h>

#define ll long long

using namespace std;
int n;
vector<pair<ll, int>> inpt;
bitset<100'020> taken;
bool used;
ll result;

int main() {
    cin >> n;
    ll temp;
    for (int i = 10; i < n + 10; i++) {
        scanf("%lld", &temp);
        inpt.emplace_back(temp, i);
    }
    sort(inpt.begin(), inpt.end(), greater<>());
    for (auto el: inpt) {
        auto [num, idx] = el;
        int onLeft, onRight;
        onLeft = taken[idx - 1];
        onRight = taken[idx + 1];
        if (onLeft && taken[idx - 2]) onLeft++;
        if (onRight && taken[idx + 2]) onRight++;

        if (onLeft + onRight <= 1) {
            taken[idx] = true;
        } else if (onLeft + onRight <= 2 && !used) {
            taken[idx] = true;
            used = true;
        }
        if (taken[idx]) result += num;
    }
    cout << result << endl;
    return 0;
}