package com.company.kolokwia.zlotejablka;

import java.util.Random;

public class Jablko {
    private int pestki;

    public Jablko() {
        Random random = new Random();
        this.pestki = random.nextInt(6) + 2;
    }

    public int getPestki() {
        return pestki;
    }
}
