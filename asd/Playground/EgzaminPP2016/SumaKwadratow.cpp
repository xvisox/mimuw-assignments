#include <bits/stdc++.h>

#define ll long long

using namespace std;

int n;
ll result;
vector<ll> secik;

ll square(ll a) {
    return a * a;
}


int main() {
    cin >> n;
    ll temp;
    scanf("%lld", &temp);
    secik.push_back(temp);

    long long tmp;
    int idx;
    for (int i = 1; i < n; i++) {
        scanf("%lld", &temp);
        auto it = lower_bound(secik.begin(), secik.end(), temp);

        // to oznacza, że bedzie na koncu
        if (it == secik.end()) {
            idx = secik.size() - 1;
            tmp = temp - secik[idx];
            result += square(tmp);
        } else {
            ll rightVal = *it;
            ll midVal = temp;
            if (it == secik.begin()) {
                tmp = rightVal - midVal;
                result += square(tmp);
            } else {
                it--;
                ll leftVal = *it;
                tmp = rightVal - leftVal;
                result -= square(tmp);

                tmp = midVal - leftVal;
                result += square(tmp);
                tmp = rightVal - midVal;
                result += square(tmp);
                it++;
            }
        }
        secik.insert(it, temp);

//        for (auto el: secik) {
//            cout << el << ' ';
//        }
//        cout << endl;
        cout << result << '\n';
    }

    return 0;
}
