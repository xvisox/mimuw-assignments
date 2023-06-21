package com.company.rolnik.warzywa;

public class Ogorek extends Warzywo {

    public Ogorek() {
        super("Ogorek", 3);
    }

    @Override
    public int zwrocWartoscWarzywa() {
        int sekunda = 1000;
        long ileCzasuUplynelo = (System.currentTimeMillis() - this.kiedyPosadzono) / sekunda;
        if (ileCzasuUplynelo <= 5) {
            return (int) (ileCzasuUplynelo * 2);
        } else if (ileCzasuUplynelo <= 10) {
            return (int) ileCzasuUplynelo;
        } else {
            return 0;
        }
    }
}
