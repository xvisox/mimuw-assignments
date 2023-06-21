package com.company.rolnik.warzywa;

public class Pomidor extends Warzywo {

    public Pomidor() {
        super("Pomidor", 4);
    }

    @Override
    public int zwrocWartoscWarzywa() {
        int sekunda = 1000;
        long ileCzasuUplynelo = (System.currentTimeMillis() - this.kiedyPosadzono) / sekunda;
        if (ileCzasuUplynelo <= 10) {
            return 0;
        } else if (ileCzasuUplynelo <= 15) {
            return (int) ((ileCzasuUplynelo - 10) * 2);
        } else {
            return (int) Math.max(10 - (ileCzasuUplynelo - 15) * 2, 0);
        }
    }
}
