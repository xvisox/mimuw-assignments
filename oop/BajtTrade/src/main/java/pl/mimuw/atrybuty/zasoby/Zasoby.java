package pl.mimuw.atrybuty.zasoby;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Data;
import lombok.EqualsAndHashCode;

import java.util.ArrayList;
import java.util.HashMap;

@EqualsAndHashCode(callSuper = true)
@Data
public class Zasoby extends AtrybutZasobow {
    @JsonProperty(access = JsonProperty.Access.READ_ONLY)
    private HashMap<TypZasoby, ArrayList<Integer>> poziomyZasobow;

    public void inicjalizujZasoby() {
        poziomyZasobow = new HashMap<>();
        poziomyZasobow.put(TypZasoby.NARZEDZIA, new ArrayList<>());
        poziomyZasobow.get(TypZasoby.NARZEDZIA).add(narzedzia);
        poziomyZasobow.put(TypZasoby.PROGRAMY, new ArrayList<>());
        poziomyZasobow.get(TypZasoby.PROGRAMY).add(programy);
        poziomyZasobow.put(TypZasoby.UBRANIA, new ArrayList<>());
        poziomyZasobow.get(TypZasoby.UBRANIA).add(ubrania);
    }

    public int dajNajwiekszyPoziom(TypZasoby produkt) {
        int maxPoziom = 0;
        for (int i = 0; i < poziomyZasobow.get(produkt).size(); i++) {
            if (poziomyZasobow.get(produkt).get(i) > 0) maxPoziom = i;
        }
        return maxPoziom + 1;
    }

    public void assertZasoby() {
        ArrayList<Integer> poziomyUbrania = poziomyZasobow.get(TypZasoby.UBRANIA);
        ArrayList<Integer> poziomyNarzedzia = poziomyZasobow.get(TypZasoby.NARZEDZIA);
        ArrayList<Integer> poziomyProgramy = poziomyZasobow.get(TypZasoby.PROGRAMY);
        int sumUbrania, sumNarzedzia, sumProgramy;
        sumUbrania = poziomyUbrania.stream()
                .mapToInt(a -> a)
                .sum();
        sumNarzedzia = poziomyNarzedzia.stream()
                .mapToInt(a -> a)
                .sum();
        sumProgramy = poziomyProgramy.stream()
                .mapToInt(a -> a)
                .sum();
        assert (sumUbrania == ubrania);
        assert (sumNarzedzia == narzedzia);
        assert (sumProgramy == programy);
    }
}
