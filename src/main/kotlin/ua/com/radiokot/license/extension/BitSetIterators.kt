@file:JvmName("BitSetIterators")

package ua.com.radiokot.license.extension

import java.util.*

fun BitSet.indices(): Iterator<Int> = object : Iterator<Int> {
    private var lastSetBit = -1

    override fun hasNext(): Boolean =
        lastSetBit != Int.MAX_VALUE && nextSetBit(lastSetBit + 1) != -1

    override fun next(): Int {
        lastSetBit = nextSetBit(lastSetBit + 1)
        return lastSetBit
    }
}

fun BitSet.indicesSequence(): Sequence<Int> =
    indices().asSequence()