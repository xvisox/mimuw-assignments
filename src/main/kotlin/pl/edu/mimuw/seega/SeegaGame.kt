package pl.edu.mimuw.seega

class SeegaGame(
    private val seegaController: SeegaController,
    private val outputPrinter: OutputPrinter,
) {

    fun run() {
        outputPrinter.printWelcomeMessage()

        outputPrinter.printBoardSizePrompt()
        val board = seegaController.createBoard()
        outputPrinter.printBoard(board)

        outputPrinter.printPhaseOnePrompt()
        while (seegaController.isPhaseOne(board)) {
            repeat(2) {
                seegaController.executeDeploy(board)
                outputPrinter.printBoard(board)
            }
            seegaController.changeColor()
        }

        outputPrinter.printGameFinishedMessage()
    }

}