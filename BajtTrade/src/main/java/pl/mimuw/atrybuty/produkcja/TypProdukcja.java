package pl.mimuw.atrybuty.produkcja;

import com.fasterxml.jackson.annotation.JsonProperty;

public enum TypProdukcja {
    @JsonProperty("chciwy") CHCIWY,
    @JsonProperty("krotkowzroczny") KROTKOWZROCZNY,
    @JsonProperty("losowy") LOSOWY,
    @JsonProperty("perspektywiczny") PERSPEKTYWICZNY,
    @JsonProperty("sredniak") SREDNIAK
}
