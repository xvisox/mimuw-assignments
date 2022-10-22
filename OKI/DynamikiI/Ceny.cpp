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
constexpr int MAX_M = (1 << 16) + 1;
constexpr int M = 18;
constexpr int MAX_N = 101;

int n, m;
int min_zakup[MAX_M], zakup[MAX_M][MAX_N], koszt[MAX_M];
int input[MAX_N][M];

void obliczZakup() {
    // zakup[mask][sklep]
    int mask = 1, max = 1 << m;
    while (mask < max) {
        for (int j = 0; j < m; j++) {
            if (mask & (1 << j)) {
                for (int i = 0; i < n; i++) {
                    zakup[mask][i] += input[i][j + 1];
                }
            }
        }
        min_zakup[mask] = INT_MAX;
        for (int i = 0; i < n; i++) {
            zakup[mask][i] += input[i][0];
            min_zakup[mask] = min(min_zakup[mask], zakup[mask][i]);
        }
        mask++;
    }
}

void obliczKoszt() {
    int max = 1 << m, subMask;
    for (int mask = 1; mask < max; mask++) {
        koszt[mask] = INT_MAX;
        subMask = mask;
        while (subMask > 0) {
            koszt[mask] = min(koszt[mask], min_zakup[subMask] + koszt[mask - subMask]);
            subMask = (subMask - 1) & mask;
        }
    }
}

// https://szkopul.edu.pl/problemset/problem/Oi53_Ox0ZJp4TPUAokh8mcYx/statement/
int main() {
    FASTIO;
    cin >> n >> m;
    for (int i = 0; i < n; i++) {
        cin >> input[i][0];
        for (int j = 1; j <= m; j++) {
            cin >> input[i][j];
        }
    }
    obliczZakup();
    obliczKoszt();
    cout << koszt[(1 << m) - 1] << endl;

    return 0;
}