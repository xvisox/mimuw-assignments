package pl.edu.mimuw.seega

import pl.edu.mimuw.seega.Constants.Companion.BLACK
import pl.edu.mimuw.seega.Constants.Companion.WHITE

class SeegaController(private val board: Board) {
    var currentPlayerColor: Char = WHITE
        private set

    fun executeDeploy(col: Char, row: Int) {
        if (!board.isFieldInBounds(col, row))
            throw Exception("Field is out of bounds.")
        if (!board.isFieldEmpty(col, row))
            throw Exception("Field is not empty.")
        board.placePawn(col, row, currentPlayerColor)
    }

    fun executeMove(col: Char, row: Int, direction: Direction): Boolean {
        if (!board.isFieldInBounds(col, row))
            throw Exception("Field is out of bounds.")
        if (!board.isFieldInBounds(col + direction.col, row + direction.row))
            throw Exception("Desired field is out of bounds.")
        if (board.isFieldEmpty(col, row))
            throw Exception("Field is empty.")
        if (!board.isFieldEmpty(col + direction.col, row + direction.row))
            throw Exception("Desired field is not empty.")
        if (board.getFieldColor(col, row) != currentPlayerColor)
            throw Exception("Field is not yours.")

        board.movePawnAndGetNewField(col, row, direction).also {
            val (newCol, newRow) = it
            return board.takeOpponentPawnsAndGetResult(newCol, newRow)
        }
    }

    fun isPhaseOne(): Boolean = board.size * board.size > board.whitePawns + board.blackPawns + 1

    fun isPhaseTwo(): Boolean = true

    fun changeColor() {
        currentPlayerColor = if (currentPlayerColor == WHITE) BLACK else WHITE
    }
}