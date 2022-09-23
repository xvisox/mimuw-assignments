package com.company.interfejsy;

import com.company.interfejsy.osoba.Osoba;

import java.util.ArrayList;

public class MainSort {
    public static void main(String[] args) {
        Bubblesort<Integer> bubblesort = new Bubblesort<>();
        Quicksort<Integer> quicksort = new Quicksort<>();
        Mergesort<Integer> mergesort = new Mergesort<>();

        ArrayList<Integer> lista = stworzListe(9, 2, 3, 15, 34, 9, 7, 41, 0);

        System.out.println(bubblesort.posortujListe(lista));
        System.out.println(quicksort.posortujListe(lista));
        System.out.println(mergesort.posortujListe(lista));

        ArrayList<Osoba> osoby = new ArrayList<>();
        osoby.add(new Osoba(1, 189, "Marek"));
        osoby.add(new Osoba(2, 160, "Bartek"));
        osoby.add(new Osoba(3, 170, "Kuba"));
        osoby.add(new Osoba(4, 175, "Patryk"));

        Mergesort<Osoba> mergeOsoby = new Mergesort<>();
        System.out.println(mergeOsoby.posortujListe(osoby));
    }

    private static ArrayList<Integer> stworzListe(int... values) {
        ArrayList<Integer> wynik = new ArrayList<>();
        for (int val : values) {
            wynik.add(val);
        }
        return wynik;
    }
}
