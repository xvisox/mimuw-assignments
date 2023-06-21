package com.company.obwod;

import java.util.ArrayList;

public class NotGate extends Gate {

    @Override
    public void setValue(ArrayList<Gate> gates) {
        value = !gates.get(0).getValue();
    }
}
