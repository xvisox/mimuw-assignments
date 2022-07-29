#include<iostream>
#include<algorithm>

#define ll long long
#define END '\n'
using namespace std;

// Ta wersja jest z sortowaniem od największych, więc przed oddaniem trzeba ją zmienić!
// Idea jest taka: liczymy prefiks i tablice największych element nieparzysty (maxNP), który się znajdują w danym prefiksie
// oraz tablice największych elementów parzystych (maxP), których nie ma w danym prefiksie.
// Złożoność:
// 1) Czas O(max(n, m))
// 2) Pamięć O(n)
int main() {
    int n, i, m, indeks;
    scanf("%d", &n);
    ll koszta[n], pref[n], maxNP[n], maxP[n];
    for (i = 0; i < n; i++) {
        scanf("%lld", &koszta[i]);
    }
    sort(koszta, koszta + n, greater<>());

    pref[0] = koszta[0];
    maxNP[0] = koszta[0] % 2 == 1 ? koszta[0] : -1;
    maxP[n - 1] = -1;
    for (i = 1; i < n; i++) {
        pref[i] = pref[i - 1] + koszta[i];
        maxNP[i] = koszta[i] % 2 == 1 ? koszta[i] : maxNP[i - 1];
    }
    for (i = n - 2; i >= 0; i--) {
        maxP[i] = koszta[i - 1] % 2 == 0 ? koszta[i - 1] : maxP[i - 1];
    }

    scanf("%d", &m);
    for (i = 0; i < m; i++) {
        scanf("%d", &indeks);
        indeks--;
        if (pref[indeks] % 2 == 1) {
            cout << pref[indeks] << END;
        } else if (maxP[indeks] != -1 && maxNP[indeks] != -1) {
            cout << (pref[indeks] - maxNP[indeks] + maxP[indeks]) << END;
        } else {
            cout << -1 << END;
        }
    }
    return 0;
}