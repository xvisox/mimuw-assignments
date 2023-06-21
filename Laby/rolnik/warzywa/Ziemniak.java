package com.company.rolnik.warzywa;

public class Ziemniak extends Warzywo {

    public Ziemniak() {
        super("Ziemniak", 2);
    }

    @Override
    public int zwrocWartoscWarzywa() {
        int sekunda = 1000;
        long ileCzasuUplynelo = (System.currentTimeMillis() - this.kiedyPosadzono) / sekunda;
        if (ileCzasuUplynelo >= 10) {
            return 5;
        } else {
            return 0;
        }
    }
}
