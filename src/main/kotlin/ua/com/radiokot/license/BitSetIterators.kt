@file:JvmName("BitSetIterators")

package ua.com.radiokot.license

import java.util.*

/**
 * @return an [Iterator] over set bits.
 */
fun BitSet.setBits(): Iterator<Int> = object : Iterator<Int> {
    private var lastSetBit = -1

    override fun hasNext(): Boolean =
        lastSetBit != Int.MAX_VALUE && nextSetBit(lastSetBit + 1) != -1

    override fun next(): Int {
        lastSetBit = nextSetBit(lastSetBit + 1)
        return lastSetBit
    }
}

/**
 * @return a [Sequence] of set bits.
 */
fun BitSet.setBitsSequence(): Sequence<Int> =
    setBits().asSequence()
