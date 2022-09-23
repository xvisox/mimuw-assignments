#include <bits/stdc++.h>

using namespace std;
int n, result;
unordered_set<long long> secik;

int main() {
    cin >> n;
    long long temp;
    long long suma = 0;
    secik.insert(0);
    for (int i = 0; i < n; i++) {
        scanf("%lld", &temp);
        suma += temp;
        if (secik.find(suma) != secik.end()) {
            result++;
            secik.clear();
            secik.insert(0);
            suma = temp;
        }
        secik.insert(suma);
    }
    cout << result;

    return 0;
}
