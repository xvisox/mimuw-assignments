#include <bits/stdc++.h>

#define FASTIO ios_base::sync_with_stdio(false); cin.tie(0), cout.tie(0)
#define ll long long
using namespace std;

int main() {
    FASTIO;
    string temp;
    cin >> temp;
    int n = temp.length();
    int last2, last6, last4, firstOdd;
    last2 = last4 = last6 = firstOdd = -1;
    for (int i = 0; i < n; i++) {
        if (temp[i] == '0' || temp[i] == '8') {
            cout << "YES\n";
            cout << temp[i] << endl;
            return 0;
        } else if (temp[i] == '2') {
            last2 = i;
        } else if (temp[i] == '4') {
            last4 = i;
        } else if (temp[i] == '6') {
            last6 = i;
        } else if (firstOdd == -1) {
            firstOdd = i;
        }
    }

    int i = last2 - 1;
    while (i >= 0) {
        if (temp[i] % 2 == 1) {
            if (temp[i] == '3' || temp[i] == '7') {
                cout << "YES\n";
                cout << temp[i] << temp[last2];
                return 0;
            } else {
                if (firstOdd != -1 && firstOdd != i) {
                    cout << "YES\n";
                    cout << temp[firstOdd] << temp[i] << temp[last2];
                    return 0;
                }
            }
        }
        i--;
    }

    i = last6 - 1;
    while (i >= 0) {
        if (temp[i] % 2 == 1) {
            if (temp[i] == '1' || temp[i] == '5' || temp[i] == '9') {
                cout << "YES\n";
                cout << temp[i] << temp[last6];
                return 0;
            } else {
                if (firstOdd != -1 && firstOdd != i) {
                    cout << "YES\n";
                    cout << temp[firstOdd] << temp[i] << temp[last6];
                    return 0;
                }
            }
        }
        i--;
    }

    i = last4 - 1;
    while (i >= 0) {
        if (temp[i] % 2 == 0) {
            if (temp[i] == '2' || temp[i] == '6') {
                cout << "YES\n";
                cout << temp[i] << temp[last4];
                return 0;
            } else {
                if (firstOdd != -1 && firstOdd < i) {
                    cout << "YES\n";
                    cout << temp[firstOdd] << temp[i] << temp[last4];
                    return 0;
                }
            }
        }
        i--;
    }

    cout << "NO\n";
    return 0;
}