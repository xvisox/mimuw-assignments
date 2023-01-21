/**
 * @file bst_with_count.cpp
 * @author Tomasz Waleń (walen@mimuw.edu.pl)
 * @brief Przykładowa implementacja wzbogaconej struktury danych.
 *        Wspierane operacje (count, kth_element).
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
    void insert(int x) {
        r = _insert(r, x);
    }

    void remove(int x) {
        r = _remove(r, x);
    }

    int count(int left, int right) {
        return _count(r, left, right);
    }

    int kth_element(int k) {
        assert (r!=NULL);
        return _kth_element(r, k);
    }

    void print() { 
        _print(r);
        printf("\n"); 
    }

private:
    struct Node {
        int value;
        int count;
        int min_value;
        int max_value;
        struct Node *left;
        struct Node *right;
        Node(int _value) : value(_value), count(1), min_value(_value), max_value(_value), left(NULL), right(NULL) { }
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
        v->min_value = (v->left != NULL ? v->left->min_value : v->value);
        v->max_value = (v->right != NULL ? v->right->max_value : v->value);
    }

    int _count_value(Node *v) {
        return (v!=NULL ? v->count : 0);
    }

    Node *_insert(Node *v, int x) {
        if (v==NULL) return new Node(x);
        if (x < v->value) v->left = _insert(v->left, x);
        else if (x > v->value) v->right = _insert(v->right, x);
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

    Node *_remove(Node *v, int x) {
        if (v==NULL) return v;
        if (x < v->value) v->left = _remove(v->left, x);
        else if (x > v->value) v->right = _remove(v->right, x);
        else {
            if (v->left == NULL) return _free_and_return(v, v->right);
            else if (v->right == NULL) return _free_and_return(v, v->left);
            else {
                Node *succ = _min_node(v->right);
                int value = succ->value;
                v->right = _remove(v->right, value);
                v->value = value;
            }
        }
        _update(v);
        return v;
    }

    int _count(Node *v, int left, int right) {
        if (v==NULL) return 0;
        if (left<=v->min_value && v->max_value<=right) return v->count;
        if (right<v->min_value || v->max_value<left) return 0;
        int res = (left<=v->value && v->value<=right) ? 1 : 0;
        res += _count(v->left, left, right);
        res += _count(v->right, left, right);
        return res;
    }

    int _kth_element(Node *v, int k) {
        assert(v!=NULL && k>=0 && k<v->count);
        int cl = (v->left != NULL ? v->left->count : 0);
        if (k < cl)
            return _kth_element(v->left, k);
        else if (k == cl)
            return v->value;
        else
            return _kth_element(v->right, k - cl - 1);
    }

    void _print(Node *v) {
        if (v==NULL) {
            printf("-");
        } else {
            printf("(v=%d,c=%d,range=[%d,%d]", v->value, v->count, v->min_value, v->max_value);
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
    int x,y;
    while(scanf("%s", (char *)&c)==1) {
        if (strcmp(c, "i")==0) {
            scanf("%d", &x);
            t.insert(x);
        } else if (strcmp(c, "r")==0) {
            scanf("%d", &x);
            t.remove(x);
        } else if (strcmp(c, "k")==0) {
            scanf("%d", &x);
            printf("%d\n", t.kth_element(x));
        } else {
            scanf("%d%d", &x, &y);
            printf("%d\n", t.count(x, y));
        }
        // t.print();
    }    
    return 0;
}