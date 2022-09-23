package com.company.kolokwia.bajaderki;

import java.util.ArrayList;

public class Przepisy {
    private ArrayList<Przepis> przepisy;

    public Przepisy() {
        this.przepisy = new ArrayList<Przepis>();
    }

    public void dodajPrzepis(Przepis przepis) {
        przepisy.add(przepis);
    }

    public void usunPrzepis(Przepis przepis) {
        przepisy.remove(przepis);
    }
}
