#include <bits/stdc++.h>

#define FASTIO ios_base::sync_with_stdio(false); cin.tie(0), cout.tie(0)
#define ll long long
#define endl '\n'
#define DEC (-1)
#define EQUAL 0
#define INC 1
using namespace std;

int n;
constexpr int MAX_N = 1e5;
ll tab[2], ile[2];
ll result = 0;

int get_state(int i, int j) {
    if (tab[i] == tab[j]) {
        return EQUAL;
    } else if (tab[i] > tab[j]) {
        return DEC;
    } else {
        return INC;
    }
}

void eval(int i) {
    if (tab[i] % 2 == 0) {
        result += ile[0];
        ile[0] = (ile[0] + 1);
        ile[1] = ile[1];
    } else {
        result += ile[1];
        swap(ile[0], ile[1]);
        ile[1]++;
    }
}

int main() {
    FASTIO;
    cin >> n;
    if (n == 1) {
        cout << 0 << endl;
        return 0;
    }

    int state = 2115;
    cin >> tab[0];
    for (int i = 2; i <= n; i++) {
        cin >> tab[1];
        int temp = get_state(0, 1);

        if (temp != state) {
            state = temp;
            ile[0] = ile[1] = 0;
            ile[tab[0] % 2]++;
            eval(1);
        } else {
            eval(1);
        }
        swap(tab[0], tab[1]);
    }
    cout << result << endl;


    return 0;
}