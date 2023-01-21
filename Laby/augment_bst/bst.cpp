#include <bits/stdc++.h>

#define FASTIO ios_base::sync_with_stdio(false); cin.tie(0), cout.tie(0)
#define ll long long
#define endl '\n'
using namespace std;

class Tree {
public:
    int data;
    Tree *left, *right;

    Tree(int data) {
        this->data = data;
        left = right = NULL;
    }
};

Tree *insert(Tree *root, int data) {
    if (root == NULL) {
        return new Tree(data);
    }
    if (data < root->data) {
        root->left = insert(root->left, data);
    } else {
        root->right = insert(root->right, data);
    }
    return root;
}

bool is_full(Tree *root, int lvl) {
    if (root == NULL) {
        return true;
    }
    if (root->left == NULL && root->right == NULL && lvl == 2) {
        return true;
    }
    if (root->left != NULL && root->right != NULL) {
        return is_full(root->left, lvl + 1) && is_full(root->right, lvl + 1);
    }
    return false;
}

void permute() {
    // An array to store the permutation
    int p[7] = {1, 2, 3, 4, 5, 6, 7};

    int count = 0;
    // While the permutation is lexicographically smaller than 1, 2, 3, 4, 5, 6, 7
    while (true) {
        Tree *root = NULL;
        for (int i: p) {
            root = insert(root, i);
        }
        if (is_full(root, 0)) {
            count++;
            for (int i: p) {
                cout << i << " ";
            }
            cout << endl;
        }

        // Generate the next permutation
        if (!std::next_permutation(p, p + 7)) {
            break;
        }
    }
    cout << count << endl;
}

int main() {
    FASTIO;
    permute();
    return 0;
}