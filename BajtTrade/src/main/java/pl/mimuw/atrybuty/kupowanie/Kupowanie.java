package pl.mimuw.atrybuty.kupowanie;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonSubTypes;
import com.fasterxml.jackson.annotation.JsonTypeInfo;
import lombok.Data;
import pl.mimuw.agenci.Robotnik;
import pl.mimuw.gielda.Gielda;

@Data
@JsonIgnoreProperties(ignoreUnknown = true)
@JsonTypeInfo(use = JsonTypeInfo.Id.NAME, include = JsonTypeInfo.As.EXISTING_PROPERTY, property = "typ", visible = true)
@JsonSubTypes({
        @JsonSubTypes.Type(value = Technofob.class, name = "technofob"),
        @JsonSubTypes.Type(value = Czyscioszek.class, name = "czyscioszek"),
        @JsonSubTypes.Type(value = Zmechanizowany.class, name = "zmechanizowany"),
        @JsonSubTypes.Type(value = Gadzeciarz.class, name = "gadzeciarz"),
})
public abstract class Kupowanie {
    private TypKupowanie typ;

    public abstract void wystawOfertyKupna(Robotnik robotnik, Gielda gielda);
}
