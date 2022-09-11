#include <bits/stdc++.h>

using namespace std;

int n, m;
constexpr int MAX_N = 500'001;

int ile[MAX_N];
vector<int> secik;
unordered_set<int> inset;

int main() {
    cin >> n >> m;

    secik.push_back(0);
    secik.push_back(n);
    int temp, rightVal, leftVal;
    int max = n;
    ile[n]++;
    for (int i = 0; i < m; i++) {
        scanf("%d", &temp);
        if (inset.find(temp) != inset.end()) {
            cout << max << '\n';
            continue;
        }

        auto it = lower_bound(secik.begin(), secik.end(), temp);
        rightVal = *it;
        it--;
        leftVal = *it;
        it++;
        secik.insert(it, temp);
        inset.insert(temp);
        ile[rightVal - temp]++;
        ile[temp - leftVal]++;
        ile[rightVal - leftVal]--;
        if (rightVal - leftVal == max && !ile[max]) {
            while (!ile[max]) max--;
        }
        cout << max << '\n';
    }

    return 0;
}