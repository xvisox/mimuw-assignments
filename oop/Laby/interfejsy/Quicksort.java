package com.company.interfejsy;

import java.util.List;

public class Quicksort<T extends Comparable<T>> implements SortowanieListy<T> {

    @Override
    public List<T> posortujListe(List<T> lista) {
        int n = lista.size();
        List<T> sorted = new java.util.ArrayList<>(List.copyOf(lista));
        quickSort(sorted, 0, n - 1);
        return sorted;
    }

    private void quickSort(List<T> list, int begin, int end) {
        if (begin < end) {
            int partitionIndex = partition(list, begin, end);
            quickSort(list, begin, partitionIndex - 1);
            quickSort(list, partitionIndex + 1, end);
        }
    }

    private void swap(List<T> list, int i, int j) {
        T temp = list.get(i);
        list.set(i, list.get(j));
        list.set(j, temp);
    }

    private int partition(List<T> list, int begin, int end) {
        T pivot = list.get(end);
        int i = (begin - 1);

        for (int j = begin; j < end; j++) {
            // list[j] <= pivot
            if (list.get(j).compareTo(pivot) < 0) {
                i++;
                swap(list, i, j);
            }
        }
        swap(list, i + 1, end);
        return i + 1;
    }

}
