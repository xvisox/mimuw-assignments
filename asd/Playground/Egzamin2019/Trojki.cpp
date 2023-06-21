#include <bits/stdc++.h>

#define ll long long

using namespace std;

int n;
ll ile[11];

int main() {
    ll result = 0;
    cin >> n;
    ll temp;
    scanf("%lld", &temp);
    ile[temp]++;

    for (int i = 1; i < n; i++) {
        scanf("%lld", &temp);
        if (temp == 1) {
            ile[temp]++;
        } else if (temp == 2) {
            result += ile[1] * (ile[1] - 1) / 2;
            ile[temp]++;
        } else {
            if (temp % 2 == 1) {
                for (int j = 1; j <= (temp / 2); j++) {
                    result += ile[j] * ile[temp - j];
                }
                ile[temp]++;
            } else {
                for (int j = 1; j < (temp / 2); j++) {
                    result += ile[j] * ile[temp - j];
                }
                result += ile[temp / 2] * (ile[temp / 2] - 1) / 2;
                ile[temp]++;
            }
        }
    }
    cout << result << endl;
    return 0;
}
