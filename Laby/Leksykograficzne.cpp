#include <bits/stdc++.h>

#define FASTIO ios_base::sync_with_stdio(false); cin.tie(0), cout.tie(0)
#define ll long long
#define endl '\n'
using namespace std;

int n, m;
int DBF[1 << 19][20];
vector<tuple<int, int, int>> aux;

int get_num(char x) {
    return x - 'a' + 1;
}

void get_row(int i) {
    for (int j = 0; j < n - ((1 << i) - 1); j++) {
        aux.emplace_back(DBF[j][i - 1], DBF[j + (1 << (i - 1))][i - 1], j);
    }
    sort(aux.begin(), aux.end());
    int next = 1;
    for (int j = 0; j < aux.size(); j++) {
        DBF[get<2>(aux[j])][i] = next;
        if (j > 0 && get<0>(aux[j]) == get<0>(aux[j - 1]) && get<1>(aux[j]) == get<1>(aux[j - 1])) {
            DBF[get<2>(aux[j])][i] = DBF[get<2>(aux[j - 1])][i];
        } else {
            next++;
        }
    }
}

void display_array() {
    for (int i = 0; (1 << i) <= n; i++) {
        for (int j = 0; j < n; j++) {
            cout << DBF[j][i] << " ";
        }
        cout << endl;
    }
}

int main() {
    FASTIO;
    cin >> n >> m;
    string s;
    cin >> s;
    for (int i = 0; i < n; i++) {
        DBF[i][0] = get_num(s[i]);
    }

//    display_array();

    for (int i = 1; (1 << i) <= n; i++) {
        get_row(i);
        aux.clear();
    }

//    display_array();

    int a, b, c, d, l1, l2, min_l;
    bool xd;
    while (m--) {
        cin >> a >> b >> c >> d;
        l1 = b - a + 1;
        l2 = d - c + 1;
        min_l = min(l1, l2);
        xd = false;

        for (int j = 19; j >= 0; j--) {
            if ((1 << j) <= min_l && (1 << j) & min_l) {
                if (DBF[a - 1][j] != DBF[c - 1][j]) {
                    if (DBF[a - 1][j] < DBF[c - 1][j]) {
                        cout << "<\n";
                    } else {
                        cout << ">\n";
                    }
                    xd = true;
                    break;
                }
                a += (1 << j);
                c += (1 << j);
            }
        }
        if (!xd) {
            if (l1 < l2) {
                cout << "<\n";
            } else if (l1 > l2) {
                cout << ">\n";
            } else {
                cout << "=\n";
            }
        }
    }

    return 0;
}