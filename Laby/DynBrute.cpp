#include <bits/stdc++.h>

#define FASTIO ios_base::sync_with_stdio(false); cin.tie(0), cout.tie(0)
#define ll long long
#define ull unsigned long long
#define pll pair<ll, ll>
#define pii pair<int, int>
#define vi vector<int>
#define vii vector<pii>
#define vl vector<ll>
#define vll vector<pll>
#define endl '\n'
using namespace std;

vi v;

void print() {
    for (auto el: v) {
        cout << el << ' ';
    }
    cout << endl;
}

void solve() {
    ll m, a, b, c, lastGet = 0, n = 0;
    cin >> m;
    char o;
    while (m--) {
        cin >> o;
        if (o == 'i') {
            cin >> a >> b >> c; // poz, element, ile
            a = (a + lastGet) % (n + 1);
            v.insert(v.begin() + a, c, b);
            print();
        } else {
            cin >> a;
            a = (a + lastGet) % n;
            lastGet = v[a]; // get
            cout << lastGet << endl;
        }
        n = v.size();
    }
}

int main() {
    FASTIO;
    solve();


    return 0;
}

//91
//17
//90
//86
//26
//99
//18
//34
//67
//
//Process finished with exit code 0