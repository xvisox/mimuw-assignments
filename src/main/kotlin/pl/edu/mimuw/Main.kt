package pl.edu.mimuw

import pl.edu.mimuw.seega.InputReader
import pl.edu.mimuw.seega.OutputPrinter
import pl.edu.mimuw.seega.SeegaController
import pl.edu.mimuw.seega.SeegaGame

fun main() {
    val inputReader = InputReader()
    val outputPrinter = OutputPrinter()

    val game = SeegaGame(inputReader, outputPrinter)
    game.run()
}
