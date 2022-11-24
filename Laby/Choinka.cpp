#include <bits/stdc++.h>

#define FASTIO ios_base::sync_with_stdio(false); cin.tie(0), cout.tie(0)
#define ul unsigned long
#define endl '\n'
using namespace std;

constexpr ul base = 1 << 18;
constexpr ul MAX_N = 200'001;
ul n, q;
ul tree_max[base << 1], tree_min[base << 1];
ul max_count[base << 1], min_count[base << 1];
ul sajz[base << 1];
ul conv[MAX_N];
vector<ul> children[MAX_N];

ul sizeSum, mini, maxi, maxSize, minSize;

void init(ul v, ul num) {
    tree_max[v] = num;
    max_count[v] = 1;
    tree_min[v] = num;
    min_count[v] = 1;
}

void add(ul v, ul num) {
    v += base;
    init(v, num);
    v /= 2;
    ul l, p;
    while (v != 0) {
        l = v << 1;
        p = l + 1;

        if (tree_min[l] == tree_min[p]) {
            tree_min[v] = tree_min[l];
            min_count[v] = min_count[l] + min_count[p];
        } else if (tree_min[l] < tree_min[p]) {
            tree_min[v] = tree_min[l];
            min_count[v] = min_count[l];
        } else {
            tree_min[v] = tree_min[p];
            min_count[v] = min_count[p];
        }

        if (tree_max[l] == tree_max[p]) {
            tree_max[v] = tree_max[l];
            max_count[v] = max_count[l] + max_count[p];
        } else if (tree_max[l] > tree_max[p]) {
            tree_max[v] = tree_max[l];
            max_count[v] = max_count[l];
        } else {
            tree_max[v] = tree_max[p];
            max_count[v] = max_count[p];
        }

        v /= 2;
    }
}

void update(ul v) {
    if (mini > tree_min[v]) {
        mini = tree_min[v];
        minSize = min_count[v];
    } else if (mini == tree_min[v]) {
        minSize += min_count[v];
    }

    if (maxi < tree_max[v]) {
        maxi = tree_max[v];
        maxSize = max_count[v];
    } else if (maxi == tree_max[v]) {
        maxSize += max_count[v];
    }
}

bool query(ul a, ul b) {
    sizeSum = sajz[b];
    mini = ULONG_MAX, minSize = 0;
    maxi = 0, maxSize = 0;

    a += base - 1;
    b += base + 1;

    while ((a / 2) != (b / 2)) {
        if (a % 2 == 0) {
            // a + 1
            update(a + 1);
        }
        if (b % 2 == 1) {
            // b - 1
            update(b - 1);
        }
        a /= 2;
        b /= 2;
    }
    return minSize >= (sizeSum - 1) || maxSize >= (sizeSum - 1);
}

void dfs(ul v, ul *next) {
    for (ul u: children[v]) {
        dfs(u, next);
    }

    conv[v] = *next;
    if (children[v].empty()) {
        sajz[*next] = 1;
    } else {
        for (ul u: children[v]) {
            sajz[*next] += sajz[conv[u]];
        }
        sajz[*next]++;
    }
    (*next)++;
}

int main() {
    FASTIO;
    cin >> n >> q;
    ul temp;
    for (ul i = 2; i <= n; i++) {
        cin >> temp;
        children[temp].push_back(i);
    }
    ul val = 0;
    fill_n(&tree_min[0], base << 1, ULONG_MAX);
    dfs(1, &val);
    for (ul i = 1; i <= n; i++) {
        cin >> temp;
        add(conv[i], temp);
    }


    char c;
    ul a, b;
    while (q--) {
        cin >> c;
        if (c == 'z') {
            cin >> a >> b;
            a = conv[a];
            add(a, b);
        } else {
            cin >> a;
            a = conv[a];
            cout << (query(a - (sajz[a] - 1), a) ? "TAK" : "NIE") << endl;
        }
    }


    return 0;
}