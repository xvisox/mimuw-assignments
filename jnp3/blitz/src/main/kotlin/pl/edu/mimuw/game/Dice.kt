package pl.edu.mimuw.game

class Dice(val sides: Int) {
    fun roll(): Int = (1..sides).random()
}