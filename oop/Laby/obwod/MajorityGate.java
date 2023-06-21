package com.company.obwod;

import java.util.ArrayList;

public class MajorityGate extends Gate {

    @Override
    public void setValue(ArrayList<Gate> gates) {
        int result = 0;
        for (Gate gate : gates) {
            if (gate.getValue()) result++;
        }
        value = result > gates.size() / 2;
    }
}
