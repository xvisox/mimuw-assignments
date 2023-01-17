#include <bits/stdc++.h>

#define FASTIO ios_base::sync_with_stdio(false); cin.tie(0), cout.tie(0)
#define ll long long
#define endl '\n'
using namespace std;

vector<int> prefix_function(string s) {
    int n = (int) s.length();
    vector<int> pi(n);
    for (int i = 1; i < n; i++) {
        int j = pi[i - 1];
        while (j > 0 && s[i] != s[j])
            j = pi[j - 1];
        if (s[i] == s[j])
            j++;
        pi[i] = j;
    }
    return pi;
}

class Solution {
public:
    long long sumScores(string s) {
        auto pref = prefix_function(s);
        vector<int> count;
        // Chodzi o to ze np. dla j = 5 i s = 'azbazbzaz'
        // to wynikiem pref[j] jest 3, czyli tak naprawde
        // wiemy, ze mamy match na pozycjach 0 oraz od j-pref[j]+1 do j.
        // Zatem dodajemy 1 ale mozemy tez przedluzyc ten prefiks
        // o tyle ile jest matchy miedzy 0 a j (a to jest policzone
        // w jtym kroku algorytmu).
        for (int k: pref) {
            count.push_back(k > 0 ? count[k - 1] + 1 : 0);
        }
        long long xd = 0;
        return accumulate(count.begin(), count.end(), xd) + s.size();
    }
};

int main() {
    FASTIO;
    auto xd = prefix_function("azbazbzaz");
    for (auto el: xd) {
        cout << el << ' ';
    }
    return 0;
}