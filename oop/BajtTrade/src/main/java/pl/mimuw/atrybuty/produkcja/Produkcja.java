package pl.mimuw.atrybuty.produkcja;

import com.fasterxml.jackson.annotation.JsonSubTypes;
import com.fasterxml.jackson.annotation.JsonTypeInfo;
import lombok.Data;
import pl.mimuw.agenci.Robotnik;
import pl.mimuw.atrybuty.zasoby.TypZasoby;
import pl.mimuw.gielda.Gielda;

@Data
@JsonTypeInfo(use = JsonTypeInfo.Id.NAME, include = JsonTypeInfo.As.EXISTING_PROPERTY, property = "typ", visible = true)
@JsonSubTypes({
        @JsonSubTypes.Type(value = Chciwy.class, name = "chciwy"),
        @JsonSubTypes.Type(value = Krotkowzroczny.class, name = "krotkowzroczny"),
        @JsonSubTypes.Type(value = Losowy.class, name = "losowy"),
        @JsonSubTypes.Type(value = Perspektywiczny.class, name = "perspektywiczny"),
        @JsonSubTypes.Type(value = Sredniak.class, name = "sredniak")
})
public abstract class Produkcja {
    private TypProdukcja typ;

    public abstract TypZasoby coDzisProdukuje(Robotnik robotnik, Gielda gielda);

    public TypZasoby zwrocNajlepszyProdukt(double maxZysk, double zyskJedzenie, double zyskNarzedzia, double zyskUbrania, double zyskProgramy) {
        if (maxZysk == zyskJedzenie) return TypZasoby.JEDZENIE;
        if (maxZysk == zyskNarzedzia) return TypZasoby.NARZEDZIA;
        if (maxZysk == zyskUbrania) return TypZasoby.UBRANIA;
        if (maxZysk == zyskProgramy) return TypZasoby.PROGRAMY;
        return null;
    }
}
