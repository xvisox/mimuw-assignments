package pl.mimuw.gielda;

import lombok.Data;

@Data
public class Info {
    private int dlugosc;
    private int kara_za_brak_ubran;
    private TypGieldy gielda;
    private Ceny ceny;
}
