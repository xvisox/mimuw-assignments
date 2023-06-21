package com.company.interfejsy.osoba;

public class Osoba implements Comparable<Osoba> {
    private final int id;
    private final int wysokosc;
    private final String imie;

    public Osoba(int id, int wysokosc, String imie) {
        this.id = id;
        this.wysokosc = wysokosc;
        this.imie = imie;
    }

    @Override
    public String toString() {
        return "Osoba{" + "id=" + id + ", wysokosc=" + wysokosc + ", imie='" + imie + '\'' + '}';
    }

    @Override
    public int compareTo(Osoba o) {
        if (this.wysokosc == o.wysokosc) {
            return 0;
        } else if (this.wysokosc > o.wysokosc) {
            return 1;
        } else {
            return -1;
        }
    }
}
