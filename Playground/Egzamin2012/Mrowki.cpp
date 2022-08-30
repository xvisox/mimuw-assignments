#include <bits/stdc++.h>

using namespace std;

int n, q;
vector<int> ipt;

void read() {
    cin >> n >> q;
    int temp;
    for (int i = 0; i < n; i++) {
        scanf("%d", &temp);
        ipt.push_back(temp);
    }
}

int main() {
    read();
    int l, r, d, ileD, ile;
    vector<int>::iterator low, up, lowD;
    for (int i = 0; i < q; i++) {
        scanf("%d %d %d", &l, &r, &d);
        low = lower_bound(ipt.begin(), ipt.end(), l);
        up = upper_bound(ipt.begin(), ipt.end(), r);
        lowD = lower_bound(low, up, d);
        ileD = 0;

        while (*lowD == d) {
            ileD++;
            lowD++;
        }
        ile = distance(low, up);
        cout << ile - ileD << endl;
        while (low != up) {
            *low = d;
            low++;
        }
    }

    return 0;
}