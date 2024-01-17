package pl.edu.mimuw.seega

enum class Field(private val symbol: Char) {
    EMPTY(' '),
    WHITE('W'),
    BLACK('B'),
    STAR('*');

    override fun toString(): String {
        return symbol.toString()
    }

    companion object {
        fun getOppositeColor(color: Field): Field {
            return if (color == WHITE) BLACK else WHITE
        }
    }
}