package pl.edu.mimuw.player

// FIXME: Zdecydowałem się na enum zamiast dziedziczenia, żeby uniknąć double dispatch albo innych instanceof.
enum class PlayerType {
    ATTACKER,
    DEFENDER
}