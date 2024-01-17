package pl.edu.mimuw.seega

enum class Field(val char: Char) {
    EMPTY(' '),
    WHITE('W'),
    BLACK('B'),
    STAR('*');

    companion object {
        fun getOppositeColor(color: Field): Field {
            return if (color == WHITE) BLACK else WHITE
        }
    }
}