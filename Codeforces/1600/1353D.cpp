#include <bits/stdc++.h>

#define PI pair<int, int>

using namespace std;
constexpr int MAX_N = 2 * 1e5 + 1;
int n, t;
int arr[MAX_N];

int neg(int x) {
    return -x;
}

void construct() {
    priority_queue<tuple<int, int, int>> q;
    int i = 1;
    int l = 0, p = n - 1, diff, mid;
    q.push({p - l + 1, -l, -p});
    while (!q.empty()) {
        tie(diff, l, p) = q.top();
        l = neg(l);
        p = neg(p);
        q.pop();
        mid = (l + p) / 2;
        arr[mid] = i++;
        if (l != p) {
            if (l <= mid - 1)
                q.push({mid - l, neg(l), neg(mid - 1)});
            if (mid + 1 <= p)
                q.push({p - mid, neg(mid + 1), neg(p)});
        }
    }
}

void print() {
    for (int i = 0; i < n; i++) {
        printf("%d ", arr[i]);
    }
    putchar('\n');
}

int main() {
    ios::sync_with_stdio(false);
    cin >> t;
    for (int i = 0; i < t; i++) {
        cin >> n;
        construct();
        print();
    }

    return 0;
}