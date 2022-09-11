#include <bits/stdc++.h>

#define ll long long

using namespace std;
ll n, d;
unordered_map<ll, char> mapka;

int main() {
    cin >> n >> d;
    ll ai;
    int ci;
    int pairs = 0;

    auto end = mapka.end();
    for (int i = 0; i < n; i++) {
        scanf("%d %lld", &ci, &ai);
        if (ci == 1) {
            // jesli ten element juz byl to nie ma co swirowac
            if (mapka[ai]) continue;

            if (mapka.find(ai - d) != end) {
                mapka[ai]++;
                mapka[ai - d]++;
                pairs++;
            }
            if (mapka.find(ai + d) != end) {
                mapka[ai]++;
                mapka[ai + d]++;
                pairs++;
            }
        } else {
            if (mapka.find(ai) == end) continue;

            if (!mapka[ai]) {
                mapka.erase(ai);
            } else {
                if (mapka.find(ai - d) != end) {
                    mapka[ai - d]--;
                    pairs--;
                }

                if (mapka.find(ai + d) != end) {
                    mapka[ai + d]--;
                    pairs--;
                }
                mapka.erase(ai);
            }
        }
        if (pairs) cout << "TAK\n";
        else cout << "NIE\n";
    }

    return 0;
}