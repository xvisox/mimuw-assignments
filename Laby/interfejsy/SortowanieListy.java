package com.company.interfejsy;

import java.util.List;

public interface SortowanieListy<T extends Comparable<T>> {
    List<T> posortujListe(List<T> lista);
}
