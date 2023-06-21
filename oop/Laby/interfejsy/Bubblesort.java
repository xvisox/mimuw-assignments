package com.company.interfejsy;

import java.util.List;

public class Bubblesort<T extends Comparable<T>> implements SortowanieListy<T> {

    @Override
    public List<T> posortujListe(List<T> lista) {
        int n = lista.size();
        List<T> sorted = new java.util.ArrayList<>(List.copyOf(lista));

        for (int i = 0; i < n - 1; i++) {
            for (int j = 0; j < n - i - 1; j++) {
                if (sorted.get(j).compareTo(sorted.get(j + 1)) > 0) {
                    T temp = sorted.get(j);
                    sorted.set(j, sorted.get(j + 1));
                    sorted.set(j + 1, temp);
                }
            }
        }
        return sorted;
    }
}


