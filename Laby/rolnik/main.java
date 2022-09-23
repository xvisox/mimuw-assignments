package com.company.rolnik;

import com.company.rolnik.rolnicy.Gospodarz;
import com.company.rolnik.rolnicy.PracownikPGR;
import com.company.rolnik.rolnicy.Rolnik;

public class main {
    public static void main(String[] args) {
//        Rolnik pracownik = new PracownikPGR(20);
//        pracownik.symulacja(20);
        Rolnik gospodarz = new Gospodarz(20);
        gospodarz.symulacja(20);
    }
}
