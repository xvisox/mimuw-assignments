#include <bits/stdc++.h>

using namespace std;

double h, c, t;

double getVal(int mid) {
    double sum = (mid + 1) * h + mid * c;
    return sum / (mid * 2 + 1);
}

bool check(int mid) {
    double val = getVal(mid);
    return val > t;
}

int main() {
    int n;
    cin >> n;

    for (int i = 0; i < n; i++) {
        scanf("%lf %lf %lf", &h, &c, &t);

        if (h == t) cout << 1;
        else if ((h + c) / 2 >= t) cout << 2;
        else {
            int l = 1, p = 1'000'000, mid;
            while (l < p) {
                mid = (l + p) / 2;
                if (check(mid)) {
                    l = mid + 1;
                } else {
                    p = mid;
                }
            }

            double valHigher = getVal(l);
            if (l > 1) {
                double valLower = getVal(l - 1);
                while (abs(valHigher - t) >= abs(valLower - t) && l > 1) {
                    l--;
                    valHigher = getVal(l);
                    valLower = getVal(l - 1);
                }
            }

            if (l == 1 && abs(getVal(l) - t) >= abs(t - h)) {
                cout << 1;
            } else cout << (2 * l) + 1;
        }
        cout << '\n';
    }

    return 0;
}