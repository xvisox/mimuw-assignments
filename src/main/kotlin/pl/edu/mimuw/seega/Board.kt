package pl.edu.mimuw.seega

import pl.edu.mimuw.seega.Constants.Companion.BLACK
import pl.edu.mimuw.seega.Constants.Companion.EMPTY
import pl.edu.mimuw.seega.Constants.Companion.FIRST_ROW_INDENT
import pl.edu.mimuw.seega.Constants.Companion.FIRST_ROW_SPACING
import pl.edu.mimuw.seega.Constants.Companion.ROW_INDENT
import pl.edu.mimuw.seega.Constants.Companion.STAR
import pl.edu.mimuw.seega.Constants.Companion.WHITE

class Board(val size: Int) {
    private val fields: Array<Array<Char>> = Array(size) { Array(size) { EMPTY } }.also { it[size / 2][size / 2] = STAR }
    var blackPawns: Int = 0
        private set
    var whitePawns: Int = 0
        private set

    fun placePawn(col: Char, row: Int, color: Char) {
        fields[rowToIndex(row)][colToIndex(col)] = color
        changePawnsCount(color, 1)
    }

    fun movePawnAndGetNewField(col: Char, row: Int, direction: Direction): Pair<Char, Int> {
        val color = fields[rowToIndex(row)][colToIndex(col)]
        val newCol = col + direction.col
        val newRow = row + direction.row

        fields[rowToIndex(row)][colToIndex(col)] = EMPTY
        fields[rowToIndex(newRow)][colToIndex(newCol)] = color
        return newCol to newRow
    }

    fun takeOpponentPawnsAndGetResult(newCol: Char, newRow: Int): Boolean {
        val takenPawns = false
        val color = fields[rowToIndex(newRow)][colToIndex(newCol)]

        for (direction in Direction.entries) {
            takenPawns or takeOpponentPawn(newCol, newRow, direction, color)
        }

        return takenPawns
    }

    fun isFieldEmpty(col: Char, row: Int): Boolean {
        return fields[rowToIndex(row)][colToIndex(col)] == EMPTY
    }

    fun isFieldInBounds(col: Char, row: Int): Boolean {
        return col in 'a'..<'a' + size && row in 1..size
    }

    fun getFieldColor(col: Char, row: Int): Char {
        return fields[rowToIndex(row)][colToIndex(col)]
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

    private fun takeOpponentPawn(col: Char, row: Int, direction: Direction, color: Char): Boolean {
        val adjacentCol = col + direction.col
        val adjacentRow = row + direction.row

        val nextAdjacentCol = adjacentCol + direction.col
        val nextAdjacentRow = adjacentRow + direction.row

        if (!isFieldInBounds(adjacentCol, adjacentRow) || fields[rowToIndex(adjacentRow)][colToIndex(adjacentCol)] == color)
            return false

        if (!isFieldInBounds(nextAdjacentCol, nextAdjacentRow) || fields[rowToIndex(nextAdjacentRow)][colToIndex(nextAdjacentCol)] != color)
            return false

        fields[rowToIndex(adjacentRow)][colToIndex(adjacentCol)] = EMPTY
        changePawnsCount(if (color == WHITE) BLACK else WHITE, -1)
        return true
    }

    private fun changePawnsCount(color: Char, change: Int) {
        if (color == WHITE)
            whitePawns += change
        else
            blackPawns += change
    }

    private fun colToIndex(col: Char): Int {
        return col - 'a'
    }

    private fun rowToIndex(row: Int): Int {
        return row - 1
    }

    private fun StringBuilder.appendRowSeparator(size: Int) {
        append("\n" + ROW_INDENT + "+---".repeat(size) + "+\n")
    }
}