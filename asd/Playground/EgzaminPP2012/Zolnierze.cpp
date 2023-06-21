#include <bits/stdc++.h>

struct node {
    int data;
    struct node *next;
    struct node *prev;
};
typedef node List;

using namespace std;
int n;
unordered_map<int, List *> mapka;

void newNode(int val) {
    List *nowa = (List *) malloc(sizeof(struct node));
    nowa->next = NULL;
    nowa->prev = NULL;
    nowa->data = val;
    mapka[val] = nowa;
}

int main() {
    cin >> n;
    for (int i = 1; i <= n; i++) {
        newNode(i);
    }
    List *last = mapka[1];
    List *curr;
    for (int i = 2; i <= n; i++) {
        curr = mapka[i];
        last->next = curr;
        curr->prev = last;

        last = curr;
    }


    int temp;
    int l, r;
    for (int i = 0; i < n; i++) {
        scanf("%d", &temp);
        curr = mapka[temp];
        if (curr->next) {
            r = curr->next->data;
            curr->next->prev = curr->prev;
        } else r = -1;

        if (curr->prev) {
            l = curr->prev->data;
            curr->prev->next = curr->next;
        } else l = -1;

        cout << l << ' ' << r << '\n';
    }

    return 0;
}