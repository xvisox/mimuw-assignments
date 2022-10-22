#include <bits/stdc++.h>

using namespace std;

void getPreimage(const int A[], int preimageA[], int n) {
    for (int i = 1; i < n; i++) {
        preimageA[A[i]] = i;
    }
}

void getLPred(const int A[], const int preimageA[], int LPred[], int n) {
    stack<int> s;
    for (int j = 1; j < n; j++) {
        int i = preimageA[j];
        // Wiemy, że zostały dodane wszystkie mniejsze wartości
        // więc teraz wystarczy, żeby indeks był mniejszy niż aktualnego elementu.
        // Możemy usuwać indeksy większe niż aktualny, bo nawet jeśli
        // kiedyś byłyby one bliżej szukanej wartości to będą mniejsze niż j.
        while (!s.empty() && s.top() > i) {
            s.pop();
        }
        if (!s.empty()) {
            LPred[i] = A[s.top()];
        } else {
            LPred[i] = -1;
        }
        s.push(i);
    }
}

void getLSucc(const int A[], const int preimageA[], int LSucc[], int n) {
    stack<int> s;
    for (int j = n - 1; j >= 1; j--) {
        int i = preimageA[j];
        while (!s.empty() && s.top() > i) {
            s.pop();
        }
        if (!s.empty()) {
            LSucc[i] = A[s.top()];
        } else {
            LSucc[i] = -1;
        }
        s.push(i);
    }
}

void print(int A[], int n) {
    for (int i = 1; i < n; i++) {
        cout << A[i] << ' ';
    }
    cout << endl;
}

int main() {
    int A[] = {-1, 3, 4, 2, 1, 6, 7, 5};
    int n = sizeof(A) / sizeof(int);
    int preimageA[n + 1];
    // LPred[i] = max{x:x belongs A[1...(i-1)] and x < A[i]}
    // LSucc[i] = min{x:x belongs A[1...(i-1)] and x > A[i]}
    int LPred[n + 1], LSucc[n + 1];
    getPreimage(A, preimageA, n);
    print(preimageA, n);
    getLPred(A, preimageA, LPred, n);
    print(LPred, n);
    getLSucc(A, preimageA, LSucc, n);
    print(LSucc, n);

    return 0;
}