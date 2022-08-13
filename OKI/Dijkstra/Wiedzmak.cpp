#include <bits/stdc++.h>

using namespace std;

constexpr int MAX_P = 1 << 14;
constexpr int MAX_N = 201;
int n, m, p, k;
bool processed[MAX_N][MAX_P];
int kowal[MAX_N], dst[MAX_N][MAX_P];

vector<tuple<int, int, int>> edges[MAX_N]; // edges[v] -> {vertex, weight, mask}

void read() {
    scanf("%d %d %d %d", &n, &m, &p, &k);
    fill_n(&dst[0][0], MAX_N * MAX_P, INT_MAX);

    int v1, v2, num, temp, weight;
    for (int i = 0; i < k; i++) {
        scanf("%d %d", &v1, &num);
        for (int j = 0; j < num; j++) {
            scanf("%d", &temp);
            kowal[v1] |= (1 << temp);
        }
    }

    int mask;
    for (int i = 0; i < m; i++) {
        mask = 0;
        scanf("%d %d %d %d", &v1, &v2, &weight, &num);
        for (int j = 0; j < num; j++) {
            scanf("%d", &temp);
            mask |= (1 << temp);
        }
        edges[v1].emplace_back(v2, weight, mask);
        edges[v2].emplace_back(v1, weight, mask);
    }
}

bool isValid(int currentMask, int toFulfill) {
    return (currentMask & toFulfill) >= toFulfill;
}

int main() {
    // n - liczba miejscowosci, m - liczba drog, p - liczba gatunkow potworow, k - liczba kowali
    read();

    priority_queue<tuple<int, int, int>> q; // {-dst, vertex, mask}
    q.push({0, 1, 0});
    dst[1][0] = 0;

    int newMask;
    while (!q.empty()) {
        auto [distance, v, msk] = q.top();
        q.pop();
        if (processed[v][msk]) continue;
        processed[v][msk] = true;

        // aktualizacja maski
        newMask = msk | kowal[v];

        for (auto element: edges[v]) {
            auto [u, weight, mask] = element;
            if (isValid(newMask, mask)) {
                if (dst[v][msk] + weight < dst[u][newMask]) {
                    dst[u][newMask] = dst[v][msk] + weight;
                    q.push({-dst[u][newMask], u, newMask});
                }
            }
        }
    }

    int res = INT_MAX;
    for (int i = 0; i < MAX_P; i++) {
        res = min(res, dst[n][i]);
    }
    if (res == INT_MAX) res = -1;
    cout << res << endl;
    return 0;
}