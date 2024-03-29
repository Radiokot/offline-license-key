package ua.com.radiokot.license.extension

import org.junit.jupiter.api.Test
import ua.com.radiokot.license.setBits
import ua.com.radiokot.license.setBitsSequence
import java.util.*
import kotlin.test.assertEquals

internal class BitSetIteratorsTest {
    @Test
    fun getIndicesSuccessfully() {
        val vectors = listOf(
            listOf(0, 2, 5, 64),
            listOf(),
            listOf(10),
            listOf(Int.MAX_VALUE),
        )

        vectors.forEach { vector ->
            val bitSet = BitSet().apply {
                vector.forEach(::set)
            }
            val indicesSet = bitSet.setBits().asSequence().toList()
            assertEquals(vector, indicesSet)
        }
    }

    @Test
    fun getIndicesSequenceSuccessfully() {
        val vectors = listOf(
            listOf(0, 2, 5, 64),
            listOf(),
            listOf(10),
            listOf(Int.MAX_VALUE),
        )

        vectors.forEach { vector ->
            val bitSet = BitSet().apply {
                vector.forEach(::set)
            }

            assertEquals(
                bitSet.setBits().asSequence().toList(),
                bitSet.setBitsSequence().toList()
            )
        }
    }
}
