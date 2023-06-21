package com.company.kalkulator;

import javax.swing.*;
import javax.swing.border.LineBorder;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

public class Calculator extends JFrame implements ActionListener {
    private final String[] symbols = {
            "AC", "+/-", "%", "/",
            "7", "8", "9", "*",
            "4", "5", "6", "-",
            "1", "2", "3", "+",
            "0", "π", "√", "="
    };
    private final JPanel panel = new JPanel(new BorderLayout(5, 5));
    private final JPanel buttonPanel = new JPanel(new GridLayout(5, 3));
    private final JButton[] buttons = new JButton[20];
    private final JTextArea screen = new JTextArea(2, 40);
    private double firstNum = 0;
    private double secondNum = 0;
    private final JTextField calculatingField = new JTextField(40);
    private int operator = 0;

    public Calculator() {
        init();
    }

    private void init() {
        setTitle("Calculator");
        screen.setFont(new Font("HelveticaNeue-Bold", Font.BOLD, 20));

        screen.setBackground(Color.BLACK);
        panel.setBackground(Color.BLACK);
        buttonPanel.setBackground(Color.BLACK);
        screen.setForeground(Color.WHITE);
        calculatingField.setBackground(Color.BLACK);
        calculatingField.setBorder(new LineBorder(Color.BLACK));

        for (int i = 0; i < buttons.length; i++) {
            buttons[i] = new JButton(symbols[i]);

            buttons[i].setOpaque(false);
            buttons[i].setBorderPainted(false);
            buttons[i].setBackground(Color.BLACK);
            buttons[i].setBackground(Color.WHITE);
            buttons[i].addActionListener(this);
            buttons[i].setFont(new Font("Times New Roman", Font.BOLD, 20));

            buttonPanel.add(buttons[i]);
        }

        panel.add(calculatingField, BorderLayout.SOUTH);
        panel.add(buttonPanel, BorderLayout.CENTER);
        panel.add(screen, BorderLayout.NORTH);
        add(panel);
        setSize(340, 400);
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setVisible(true);
    }

    public static void main(String[] args) {
        new Calculator();
    }

    private Double getNumber() {
        if (screen.getText().equals("π")) return Math.PI;
        return Double.parseDouble(screen.getText());
    }

    @Override
    public void actionPerformed(ActionEvent e) {
        String command = e.getActionCommand();

        switch (command) {
            case "0":
                screen.setText(screen.getText() + "0");
                break;
            case "1":
                screen.setText(screen.getText() + "1");
                break;
            case "2":
                screen.setText(screen.getText() + "2");
                break;
            case "3":
                screen.setText(screen.getText() + "3");
                break;
            case "4":
                screen.setText(screen.getText() + "4");
                break;
            case "5":
                screen.setText(screen.getText() + "5");
                break;
            case "6":
                screen.setText(screen.getText() + "6");
                break;
            case "7":
                screen.setText(screen.getText() + "7");
                break;
            case "8":
                screen.setText(screen.getText() + "8");
                break;
            case "9":
                screen.setText(screen.getText() + "9");
                break;
            case "π":
                screen.setText("π");
                break;
            case "+":
                if (!screen.getText().isEmpty()) {
                    firstNum = getNumber();
                    screen.setText("");
                    operator = 1;
                }
                break;
            case "-":
                if (!screen.getText().isEmpty()) {
                    firstNum = getNumber();
                    screen.setText("");
                    operator = 2;
                }
                break;
            case "*":
                if (!screen.getText().isEmpty()) {
                    firstNum = getNumber();
                    screen.setText("");
                    operator = 3;
                }
                break;
            case "/":
                if (!screen.getText().isEmpty()) {
                    firstNum = getNumber();
                    screen.setText("");
                    operator = 4;
                }
                break;
            case "%":
                if (!screen.getText().isEmpty()) {
                    firstNum = getNumber();
                    operator = 5;
                }
                break;
            case "√":
                firstNum = Math.sqrt(getNumber());
                screen.setText(String.valueOf(firstNum));
                break;
            case "AC":
                screen.setText("");
                break;
            case "+/-":
                firstNum = (-1) * getNumber();
                screen.setText(String.valueOf(firstNum));
                break;
        }
        if (command.equalsIgnoreCase("=") && !screen.getText().isEmpty()) {
            secondNum = getNumber();

            switch (operator) {
                case 1:
                    screen.setText(String.valueOf(firstNum + secondNum));
                    calculatingField.setText(firstNum + "+" + secondNum + "=" + (firstNum + secondNum));
                    break;
                case 2:
                    screen.setText(String.valueOf(firstNum - secondNum));
                    calculatingField.setText(firstNum + "-" + secondNum + "=" + (firstNum - secondNum));
                    break;
                case 3:
                    screen.setText(String.valueOf(firstNum * secondNum));
                    calculatingField.setText(firstNum + "*" + secondNum + "=" + (firstNum * secondNum));
                    break;
                case 4:
                    screen.setText(String.valueOf(firstNum / secondNum));
                    calculatingField.setText(firstNum + "/" + secondNum + "=" + (firstNum / secondNum));
                    break;
                case 5:
                    screen.setText(String.valueOf(firstNum % secondNum));
                    calculatingField.setText(firstNum + "%" + secondNum + "=" + (firstNum % secondNum));
                    break;
            }
        }
    }
}
