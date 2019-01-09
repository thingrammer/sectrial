package com.example.demo

//@ExtendWith(SpringExtension::class)
class Basic(val max: Int) {
    operator fun invoke(arg: Any) {
        }


    operator fun minus(arg: Any) {

    }

    operator fun times(arg: Any) {

    }
}

fun main() {
    var f1 = { x: Basic -> x * x(x - 1) }
    println(f1(Basic(12)))


}