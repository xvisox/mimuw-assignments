package pl.edu.mimuw.seega

import pl.edu.mimuw.seega.Constants.Companion.BLACK
import pl.edu.mimuw.seega.Constants.Companion.WHITE

class SeegaController(private val board: Board) {
    var currentColor: Char = WHITE
        private set

    fun executeDeploy(col: Char, row: Int) {
        if (!board.isFieldInBounds(col, row)) throw Exception("Field is out of bounds.")
        if (!board.isFieldEmpty(col, row)) throw Exception("Field is not empty.")
        board.placePawn(col, row, currentColor)
    }

    fun executeMove(col: Char, row: Int, direction: Direction): Boolean {
        return false
    }

    fun isPhaseOne(): Boolean = board.size * board.size > board.pawns

    fun isPhaseTwo(): Boolean = true

    fun changeColor() {
        currentColor = if (currentColor == WHITE) BLACK else WHITE
    }
}