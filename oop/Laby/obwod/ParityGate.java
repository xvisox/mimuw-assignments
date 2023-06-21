package com.company.obwod;

import java.util.ArrayList;

public class ParityGate extends Gate {

    @Override
    public void setValue(ArrayList<Gate> gates) {
        int result = 0;
        for (Gate gate : gates) {
            if (gate.getValue()) result++;
        }
        value = result % 2 == 1;
    }
}
