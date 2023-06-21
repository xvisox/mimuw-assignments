#include <bits/stdc++.h>

#define FASTIO ios_base::sync_with_stdio(false); cin.tie(0), cout.tie(0)
#define ul unsigned long
#define endl '\n'
using namespace std;

constexpr int MAX_N = 1e9 + 1;
constexpr int base = 1 << 17;
ul tree[base << 1];
unordered_map<ul, ul> conv;
ul next_idx = 0;
int n;

ul get_gcd(ul idx) {
    ul l = idx << 1;
    ul r = l + 1;
    if (tree[l] > 0 && tree[r] > 0)
        return gcd(tree[l], tree[r]);
    else if (tree[l] > 0)
        return tree[l];
    else
        return tree[r];
}

void add(ul val) {
    ul idx = next_idx++;

    conv[val] = idx;
    idx += base;
    tree[idx] = val;
    idx >>= 1;
    while (idx) {
        tree[idx] = get_gcd(idx);
        idx >>= 1;
    }
}

void remove(ul val) {
    ul idx = conv[val];

    idx += base;
    tree[idx] = 0;
    idx >>= 1;
    while (idx) {
        tree[idx] = get_gcd(idx);
        idx >>= 1;
    }
}

int main() {
    FASTIO;
    cin >> n;
    char c;
    ul val;
    while (n--) {
        cin >> c >> val;
        if (c == '+')
            add(val);
        else
            remove(val);
        cout << max(tree[1], 1UL) << endl;
    }


    return 0;
}