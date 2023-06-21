package com.company.kolokwia.blyskawica;

public class Karta {
    String kolor;
    String wartosc;

    public Karta(String kolor, String wartosc) {
        this.kolor = kolor;
        this.wartosc = wartosc;
    }

    public int zwrocWartoscKarty() {
        String[] wartosci = new String[]{"1", "2", "3", "4", "5", "6", "7", "8", "9", "10", "walet", "dama", "krol", "as"};
        String[] kolory = new String[]{"trefl", "karo", "kier", "pik"};
        int w1, w2;
        w1 = w2 = 0;
        int i = 0;
        for (String wartosc : wartosci) {
            if (wartosc.equals(this.wartosc)) {
                w1 = i;
                break;
            }
            i++;
        }
        i = 0;
        for (String kolor : kolory) {
            if (kolor.equals(this.kolor)) {
                w2 = i;
                break;
            }
            i++;
        }
        return w1 * 10 + w2;
    }
}
