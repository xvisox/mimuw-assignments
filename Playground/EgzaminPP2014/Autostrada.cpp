#include <bits/stdc++.h>

#define FASTIO ios_base::sync_with_stdio(false); cin.tie(0), cout.tie(0)
#define ll long long
#define endl '\n'
using namespace std;

constexpr int MAX_N = 5e5 + 1;
constexpr int base = 1 << 3;
bool k_up[base * 2], k_down[base * 2];
bool p_up[base * 2], p_down[base * 2];
bool flooor[MAX_N];
int n, m;

string wrap(int i, int j) {
    return "(" + to_string(i) + "," + to_string(j) + ")";
}

void print(bool p1, bool p2) {
    int count = 1;
    int counter = 0;
    for (int i = 1; i < base * 2; i++) {
        if (p1) cout << wrap(k_up[i], k_down[i]) << " ";
        if (p2) cout << wrap(p_up[i], p_down[i]) << " ";
        counter++;
        if (counter == count) {
            count *= 2;
            counter = 0;
            cout << endl;
        }
    }

    cout << endl;
}

void update(int v, int op) {
    switch (op) {
        case 0:
            flooor[v] = !flooor[v];
            break;
        case 1:
            v += base;
            k_down[v] = !k_down[v];
            p_down[v] = !p_down[v];
            break;
        case 2:
            v += base;
            k_up[v] = !k_up[v];
            p_up[v] = !p_up[v];
            break;
    }
}

void eval(int v, int end) {
    int l = 2 * v, r = 2 * v + 1;
    bool pocz_gora = p_up[l], koniec_gora = k_up[r];
    bool pocz_dol = p_down[l], koniec_dol = k_down[r];

    bool pocz_srodek_gora = k_up[l], koniec_srodek_gora = p_up[r];
    bool pocz_srodek_dol = k_down[l], koniec_srodek_dol = p_down[r];

    bool podloga = flooor[end];

    k_up[v] = k_down[v] = false;

    k_up[v] = (pocz_srodek_gora && koniec_srodek_gora) || (pocz_srodek_dol && !podloga);
    k_down[v] = (pocz_srodek_dol && koniec_srodek_dol) || (pocz_srodek_gora && !podloga);

    p_up[v] = min(pocz_gora, k_up[v]);
    p_down[v] = min(pocz_dol, k_down[v]);
}

void add(int v) {
    int r = (v / 2) * 2, x = 1;
    v += base;
    v /= 2;
    while (v) {
        eval(v, r);
        v /= 2;
        r += x;
        x *= 2;
    }
}

// zly solve, moze kiedys mnie oswieci
int main() {
    FASTIO;
    cin >> n >> m;
    int range = base * 2;
    for (int i = 0; i < range; i++) {
        k_down[i] = k_up[i] = p_down[i] = p_up[i] = true;
    }
    int v, op;
    while (m--) {
        cin >> v >> op;
        update(v, op);
        add(v);
        if (p_up[1] || p_down[1]) {
            cout << "TAK" << endl;
        } else {
            cout << "NIE" << endl;
        }
    }
//    print(true, false);
//    print(false, true);

    return 0;
}
//
// 10 5
// 2 0
// 4 0
// 2 1
// 5 2
// 3 0
