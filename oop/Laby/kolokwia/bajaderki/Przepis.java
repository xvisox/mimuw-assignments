package com.company.kolokwia.bajaderki;

public class Przepis {
    private int P; // ile stron ma przepis (tak zostalo oznaczone)
    private int[] numeryStron;

    public int[] getNumeryStron() {
        return numeryStron;
    }

    public void setNumeryStron(int[] numeryStron) {
        this.numeryStron = numeryStron;
    }

    public int getP() {
        return P;
    }
}
