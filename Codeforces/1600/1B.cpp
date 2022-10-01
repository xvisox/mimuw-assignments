#include <bits/stdc++.h>

#define FASTIO ios_base::sync_with_stdio(false); cin.tie(0), cout.tie(0)
#define ll long long
#define pll pair<ll, ll>
#define pii pair<int, int>
#define vi vector<int>
#define vii vector<pii>
#define vl vector<ll>
#define vll vector<pll>
#define endl '\n'
using namespace std;
int n;
unordered_map<char, int> mapka = {{'A', 1},
                                  {'B', 2},
                                  {'C', 3},
                                  {'D', 4},
                                  {'E', 5},
                                  {'F', 6},
                                  {'G', 7},
                                  {'H', 8},
                                  {'I', 9},
                                  {'J', 10},
                                  {'K', 11},
                                  {'L', 12},
                                  {'M', 13},
                                  {'N', 14},
                                  {'O', 15},
                                  {'P', 16},
                                  {'Q', 17},
                                  {'R', 18},
                                  {'S', 19},
                                  {'T', 20},
                                  {'U', 21},
                                  {'V', 22},
                                  {'W', 23},
                                  {'X', 24},
                                  {'Y', 25},
                                  {'Z', 26}
};


void typ1(string temp) {
    int j = temp.length() - 1;
    int column = 0, row = 0, mnoznik = 1;
    while (temp[j] != 'C') {
        column += (mnoznik * (temp[j] - '0'));
        mnoznik *= 10;
        j--;
    }
    mnoznik = 1;
    j--;
    while (j > 0) {
        row += (mnoznik * (temp[j] - '0'));
        mnoznik *= 10;
        j--;
    }
    vi v;
    while (column > 0) {
        v.push_back(column % 26);
        if (column % 26 == 0) {
            column /= 26;
            column--;
        } else column /= 26;
    }
    j = v.size() - 1;
    while (j >= 0) {
        if (v[j] == 0) cout << 'Z';
        else cout << (char) ('A' + v[j] - 1);
        j--;
    }
    cout << row << endl;
}

void typ2(string temp) {
    int i = temp.length() - 1;
    int row = 0, column = 0;
    int mnoznik = 1;
    while (isdigit(temp[i])) {
        row += (temp[i] - '0') * mnoznik;
        i--;
        mnoznik *= 10;
    }
    cout << 'R' << row << 'C';
    mnoznik = 1;
    while (i >= 0) {
        column += mnoznik * (mapka[temp[i]]);
        mnoznik *= 26;
        i--;
    }
    cout << column << endl;
}

void solve() {
    string temp;
    for (int i = 0; i < n; i++) {
        cin >> temp;
        int j = 0;
        while (!isdigit(temp[j])) j++;
        while (isdigit(temp[j])) j++;
        if (j == temp.length()) {
            typ2(temp);
        } else typ1(temp);
    }
}

int main() {
    FASTIO;
    cin >> n;
    solve();

    return 0;
}