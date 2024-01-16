package pl.edu.mimuw.seega

class OutputPrinter {

    fun printWelcomeMessage() {
        println("Welcome to Seega game!")
    }

    fun printBoardSizePrompt() {
        println("Choose board size:")
        println("5. 5x5")
        println("7. 7x7")
        println("9. 9x9")
    }

    fun printGameFinishedMessage() {
        println("Game finished. Thank you for playing!")
    }

    fun printBoard(board: Board) {
        println(board)
    }

    fun printPhaseOnePrompt() {
        println("Phase 1: place your pawns on the board.")
    }

    fun printPhaseTwoPrompt() {
        println("Phase 2: move your pawns on the board.")
    }

}