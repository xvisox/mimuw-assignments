package pl.edu.mimuw.seega

import pl.edu.mimuw.seega.Utils.Companion.retry

class SeegaGame(
    private val inputReader: InputReader,
    private val outputPrinter: OutputPrinter,
) {

    fun run() {
        outputPrinter.printWelcomeMessage()

        outputPrinter.printBoardSizePrompt()
        val board = retry { Board(inputReader.readBoardSize()) }
        outputPrinter.printBoard(board)

        outputPrinter.printPhaseOnePrompt()
        val seegaController = SeegaController(board)
        while (seegaController.isPhaseOne()) {
            repeat(2) {
                retry {
                    val (col, row) = inputReader.readDeployCommand()
                    seegaController.executeDeploy(col, row)
                    outputPrinter.printBoard(board)
                }
            }
            seegaController.changeColor()
        }

        outputPrinter.printGameFinishedMessage()
    }

}