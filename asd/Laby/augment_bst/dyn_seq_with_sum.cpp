/**
 * @file dyn_seq_with_sum.cpp
 * @author Tomasz Waleń (walen@mimuw.edu.pl)
 * @brief Przykładowa implementacja wzbogaconej struktury danych
 *        dla zadania Dynamiczny Ciąg.
 *        Wspierane operacje (insert, remove, sum).
 *        Program używa zwykłego drzewa więc pesymistyczny czas
 *        wszystkich operacji to O(n).
 * @version 0.1
 * @date 2021-12-19
 * 
 * @copyright Copyright (c) 2021
 * 
 */
#include<iostream>
#include<cassert>
#include<cstring>

using namespace std;

class Solution {
public:
    void insert(int i, int x) {
        assert ((r==NULL && i==0) || (r!=NULL && i>=0 && i<=r->count));
        r = _insert(r, i, x);
    }

    void remove(int i) {
        assert (r!=NULL && i>=0 && i<r->count);
        r = _remove(r, i);
    }

    int sum(int i, int j) {
        assert (r!=NULL && 0<=i && i<=j && j<r->count);
        return _sum(r, i, j);
    }

    void print() { 
        _print(r);
        printf("\n"); 
    }

private:
    struct Node {
        int value;
        int count;
        int sum;
        struct Node *left;
        struct Node *right;
        Node(int _value) : value(_value), count(1), sum(_value), left(NULL), right(NULL) { }
    };
    struct Node *r=NULL;

    /**
     * @brief Aktualizuje dodatkowe atrybuty w węźle v
     * 
     * @param v 
     */
    void _update(Node *v) {
        assert(v!=NULL);
        v->count = 1 + _count_value(v->left) + _count_value(v->right); 
        v->sum = v->value + _sum_value(v->left) + _sum_value(v->right); 
    }

    int _count_value(Node *v) {
        return (v!=NULL ? v->count : 0);
    }

    int _sum_value(Node *v) {
        return (v!=NULL ? v->sum : 0);
    }

    Node *_insert(Node *v, int i, int x) {
        if (v==NULL) {
            assert (i==0);
            return new Node(x);
        }
        if (i <= _count_value(v->left)) 
            v->left = _insert(v->left, i, x);
        else
            v->right = _insert(v->right, i - _count_value(v->left) - 1, x);
        _update(v);
        return v;
    }

    Node *_free_and_return(Node *node_to_free, Node *node_to_return) {
        free(node_to_free);
        return node_to_return;
    }

    Node *_min_node(Node *v) {
        if (v==NULL || v->left==NULL)
            return v;
        else
            return _min_node(v->left);
    }

    Node *_remove(Node *v, int i) {
        assert(v!=NULL);

        if (i < _count_value(v->left))
            v->left = _remove(v->left, i);
        else if (i==_count_value(v->left)) {
            return _remove_node(v);
        } else {
            v->right = _remove(v->right, i - _count_value(v->left) - 1);
        }
        _update(v);
        return v;
    }

    Node *_remove_node(Node *v) {
        if (v->left == NULL) return _free_and_return(v, v->right);
        else if (v->right == NULL) return _free_and_return(v, v->left);
        else {
            Node *succ = _min_node(v->right);
            int value = succ->value;
            v->right = _remove(v->right, 0);
            v->value = value;
            _update(v);
        }
        return v;
    }

    int _sum(Node *v, int i, int j) {
        if (v==NULL) return 0;
        assert(0<=i && i<=j && j<v->count);
        if (i==0 && j==v->count-1) {
            return v->sum;
        } else {
            int res = 0;
            int cl = _count_value(v->left);
            if (i<cl) res += _sum(v->left, i, min(j, cl - 1));
            if (i<=cl && cl<=j) res += v->value;
            if (cl<j) res += _sum(v->right, max(0, i - cl - 1), j - cl - 1);
            return res;
        }
    }

    void _print(Node *v) {
        if (v==NULL) {
            printf("-");
        } else {
            printf("(v=%d,c=%d,sum=%d,", v->value, v->count, v->sum);
            _print(v->left);
            printf(",");
            _print(v->right);
            printf(")");
        }
    }
};

int main(void) {
    Solution t;
    char c[10];
    int i,x,l,r;
    while(scanf("%s", (char *)&c)==1) {
        if (strcmp(c, "i")==0) {
            scanf("%d", &i);
            scanf("%d", &x);
            t.insert(i, x);
        } else if (strcmp(c, "r")==0) {
            scanf("%d", &i);
            t.remove(i);
        } else {
            scanf("%d%d", &l, &r);
            printf("%d\n", t.sum(l, r));
        }
        // t.print();
    }    
    return 0;
}