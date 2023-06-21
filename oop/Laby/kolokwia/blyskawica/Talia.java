package com.company.kolokwia.blyskawica;

import java.util.Random;

public class Talia {
    private Karta[] karty;

    public Talia() {
        karty = new Karta[52];
        String[] wartosci = new String[]{"1", "2", "3", "4", "5", "6", "7", "8", "9", "10", "walet", "dama", "krol", "as"};
        String[] kolory = new String[]{"trefl", "karo", "kier", "pik"};
        int k = 0;
        for (String value : wartosci) {
            for (String str : kolory) {
                karty[k++] = new Karta(str, value);
            }
        }
    }

    public Karta[] getKarty() {
        return karty;
    }

    public void tasuj() {
        Karta[] tasowanie = new Karta[52];
        int j = 0;
        for (int i = 0; i < 26; i++) {
            tasowanie[j++] = karty[i];
            tasowanie[j++] = karty[i + 26];
        }
        Random random = new Random();
        int podzial = random.nextInt(51) + 1;
        mirror(tasowanie, 0, 52 - podzial - 1);
        mirror(tasowanie, 52 - podzial, 52);
        mirror(tasowanie, 0, 52);
    }

    private void mirror(Karta[] karty, int pocz, int kon) {
        // do sth
    }
}
