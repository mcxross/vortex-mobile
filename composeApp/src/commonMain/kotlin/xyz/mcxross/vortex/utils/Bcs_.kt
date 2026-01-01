package xyz.mcxross.vortex.utils

import com.ionspin.kotlin.bignum.integer.BigInteger

object Bcs_ {
  fun serializeU256(value: String): ByteArray {
    if (value.isEmpty()) return ByteArray(32)
    val bigInt = BigInteger.parseString(value)
    val bytes = bigInt.toByteArray()
    val result = ByteArray(32)
    val start = if (bytes.size > 32 && bytes[0] == 0.toByte()) 1 else 0
    val length = minOf(bytes.size - start, 32)

    for (i in 0 until length) {
      result[i] = bytes[bytes.size - 1 - i]
    }

    return result
  }
}
