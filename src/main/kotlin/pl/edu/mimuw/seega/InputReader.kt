package pl.edu.mimuw.seega

class InputReader {

    fun readBoardSize(): Int {
        return when (readln()) {
            "5" -> 5
            "7" -> 7
            "9" -> 9
            else -> throw Exception("Invalid board size.")
        }
    }

    fun readDeployCommand(): Pair<Char, Int> {
        val input = readln()
        val result = Constants.DEPLOY_PATTERN.matchEntire(input) ?: throw Exception("Invalid deploy command.")
        val field = result.value.split(' ')[1]
        return field[0] to field[1] - '0'
    }
}