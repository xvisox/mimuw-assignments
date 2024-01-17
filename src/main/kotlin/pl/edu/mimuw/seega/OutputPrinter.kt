package pl.edu.mimuw.seega

import pl.edu.mimuw.seega.Constants.Companion.SMALL_BOARD_SIZE
import pl.edu.mimuw.seega.Constants.Companion.MEDIUM_BOARD_SIZE
import pl.edu.mimuw.seega.Constants.Companion.LARGE_BOARD_SIZE

class OutputPrinter {

    fun printWelcomeMessage() {
        println("Welcome to Seega game!")
    }

    fun printBoardSizePrompt() {
        println("Choose board size:")
        println("${SMALL_BOARD_SIZE}. ${SMALL_BOARD_SIZE}x${SMALL_BOARD_SIZE}")
        println("${MEDIUM_BOARD_SIZE}. ${MEDIUM_BOARD_SIZE}x${MEDIUM_BOARD_SIZE}")
        println("${LARGE_BOARD_SIZE}. ${LARGE_BOARD_SIZE}x${LARGE_BOARD_SIZE}")
    }

    fun printGameFinishedMessage() {
        println("Game finished. Thank you for playing!")
    }

    fun printBoard(board: Board) {
        println(board)
    }

    fun printPlayerTurn(color: PawnColor) {
        when (color) {
            PawnColor.WHITE -> println("White player's turn.")
            PawnColor.BLACK -> println("Black player's turn.")
            else -> throw IllegalArgumentException("Invalid color: $color")
        }
    }

    fun printWonMessage(color: PawnColor) {
        when (color) {
            PawnColor.WHITE -> println("White player won!")
            PawnColor.BLACK -> println("Black player won!")
            else -> print("Draw!")
        }
    }

    fun printPhaseOnePrompt() {
        println("Phase 1: place your pawns on the board.")
    }

    fun printPhaseTwoPrompt() {
        println("Phase 2: move your pawns on the board.")
    }

}