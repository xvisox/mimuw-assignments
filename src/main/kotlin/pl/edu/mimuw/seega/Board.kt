package pl.edu.mimuw.seega

import pl.edu.mimuw.seega.Constants.Companion.FIRST_ROW_INDENT
import pl.edu.mimuw.seega.Constants.Companion.FIRST_ROW_SPACING
import pl.edu.mimuw.seega.Constants.Companion.ROW_INDENT

class Board(val size: Int) {
    private val fields: Array<Array<Char>> = Array(size) { Array(size) { ' ' } }.also { it[size / 2][size / 2] = '*' }

    var pawns: Int = 1
        private set

    fun placePawn(col: Char, row: Int, color: Char) {
        fields[row - 1][col - 'a'] = color
        pawns++
    }

    fun isFieldEmpty(col: Char, row: Int): Boolean {
        return fields[row - 1][col - 'a'] == ' '
    }

    fun isFieldInBounds(col: Char, row: Int): Boolean {
        return col in 'a'..<'a' + size && row in 1..size
    }

    override fun toString(): String {
        val stringBuilder = StringBuilder()

        stringBuilder.append(FIRST_ROW_INDENT)
        for (i in 0 until size) {
            stringBuilder.append("${('a' + i)}${FIRST_ROW_SPACING}")
        }

        stringBuilder.appendRowSeparator(size)
        for (i in fields.indices) {
            stringBuilder.append(" ${i + 1} |")
            for (j in fields[i].indices) {
                stringBuilder.append(" ${fields[i][j]} |")
            }
            stringBuilder.appendRowSeparator(size)
        }

        return stringBuilder.toString()
    }

    private fun StringBuilder.appendRowSeparator(size: Int) {
        append("\n" + ROW_INDENT + "+---".repeat(size) + "+\n")
    }
}