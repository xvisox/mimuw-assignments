#include <bits/stdc++.h>

#define FASTIO ios_base::sync_with_stdio(false); cin.tie(0), cout.tie(0)
#define G 'G'
#define A 'A'
#define U 'U'
#define C 'C'
#define endl '\n'
using namespace std;

constexpr int MAX_N = 1e5 + 2115; // pozdrawiam prawdziwych graczy
unordered_map<string, string> conv;
int n, q;

int dp_normal[MAX_N], dp_changed[MAX_N];

int count(string &curr, string &prev, int placeholder) {
    if (curr.empty() || prev.empty()) return placeholder;
    int res = 0;
    if (curr[0] == G) {
        if (prev[0] == G) res++;
        if (prev[1] == G) res++;
        if (prev[2] == G) res++;
    }
    if (curr[1] == G) {
        if (prev[2] == G) res++;
        if (prev[1] == G) res++;
        if (curr[0] == G) res++;
    }
    if (curr[2] == G) {
        if (curr[0] == G) res++;
        if (curr[1] == G) res++;
        if (prev[2] == G) res++;
    }
    return res;
}

int main() {
    FASTIO;
    string a, b, temp;
    cin >> n >> q;
    cin >> temp;
    while (q--) {
        cin >> a >> b;
        conv[a] = b;
    }

    string word = "XXX" + temp;

    int i = 3;
    dp_changed[i] = dp_normal[i] = 0;
    i++;
    dp_changed[i] = dp_normal[i] = (word[i - 1] == word[i] && word[i - 1] == G);
    i++;

    string prev, curr, curr_changed, prev_changed;
    // i = 5
    for (; i < n + 3; i++) {
        curr = word.substr(i - 2, 3);
        prev = word.substr(i - 5, 3);
        curr_changed = conv[curr];
        prev_changed = conv[prev];

        int normal = count(curr, prev, 2115);
        int changed = count(curr_changed, prev_changed, normal);
        int normal_changed = count(curr, prev_changed, normal);
        int changed_normal = count(curr_changed, prev, normal);

        dp_normal[i] = min(normal + dp_normal[i - 3], normal_changed + dp_changed[i - 3]);
        dp_changed[i] = min(changed_normal + dp_normal[i - 3], changed + dp_changed[i - 3]);
    }

    cout << min(dp_normal[n + 2], dp_changed[n + 2]) << endl;

//    cout << temp << '*';
//    for (const auto &p: conv) {
//        if (p.second.empty()) continue;
//        cout << p.first << "-" << p.second << '|';
//    }
//    cout << endl;

    return 0;
}

