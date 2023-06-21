package com.company.interfejsy;

import java.util.ArrayList;
import java.util.List;

public class Mergesort<T extends Comparable<T>> implements SortowanieListy<T> {

    @Override
    public List<T> posortujListe(List<T> lista) {
        int n = lista.size();
        List<T> sorted = new java.util.ArrayList<>(List.copyOf(lista));
        return mergeSort(sorted);
    }

    public List<T> mergeSort(List<T> list) {
        if (list.size() < 2) {
            return list;
        }
        int mid = list.size() / 2;
        return merged(mergeSort(list.subList(0, mid)), mergeSort(list.subList(mid, list.size())));
    }

    private List<T> merged(List<T> left, List<T> right) {
        int leftIndex = 0;
        int rightIndex = 0;
        List<T> merged = new ArrayList<>();

        while (leftIndex < left.size() && rightIndex < right.size()) {
            if (left.get(leftIndex).compareTo(right.get(rightIndex)) < 0) {
                merged.add(left.get(leftIndex++));
            } else {
                merged.add(right.get(rightIndex++));
            }
        }
        merged.addAll(left.subList(leftIndex, left.size()));
        merged.addAll(right.subList(rightIndex, right.size()));
        return merged;
    }
}
