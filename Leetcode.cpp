#include <bits/stdc++.h>

using namespace std;

class Solution {
#define ll long long
#define MOD 1e9 + 7;
public:
    int countVowelPermutation(int n) {
        ll dp[n + 1][5];
        ll mod = MOD;
        for (int i = 0; i < 5; i++) dp[1][i] = 1;

        for (int i = 2; i <= n; i++) {
            for (int j = 0; j < 5; j++) {
                switch (j) {
                    case 0:
                        dp[i][j] = dp[i - 1][1] + dp[i - 1][2] + dp[i - 1][4];
                        break;
                    case 1:
                        dp[i][j] = dp[i - 1][0] + dp[i - 1][2];
                        break;
                    case 2:
                        dp[i][j] = dp[i - 1][1] + dp[i - 1][3];
                        break;
                    case 3:
                        dp[i][j] = dp[i - 1][2];
                        break;
                    case 4:
                        dp[i][j] = dp[i - 1][3] + dp[i - 1][2];
                        break;
                }
                dp[i][j] %= mod;
            }
        }
        ll result = 0;
        for (int i = 0; i < 5; i++) result = (result + dp[n][i]) % mod;
        return result;
    }
};

int main() {

}