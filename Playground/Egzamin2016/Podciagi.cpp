#include <bits/stdc++.h>

#define MAX_N 1'000'001
#define ll long long

using namespace std;

ll result;
int n;

int main() {
    cin >> n;

    ll ile1, ile2, ile12, temp, ilePar;
    ile1 = ile2 = ile12 = ilePar = 0;
    for (int i = 0; i < n; i++) {
        scanf("%lld", &temp);
        if (temp == 1) {
            ile1++;
        } else if (temp == 2) {
            ile12 += ile1;
            ilePar += ile1;
            ile2++;
        } else {
            ilePar += (ile1 + ile2);
            result += ile12;
        }
    }
    result += (ilePar + n);
    cout << result << endl;
    return 0;
}