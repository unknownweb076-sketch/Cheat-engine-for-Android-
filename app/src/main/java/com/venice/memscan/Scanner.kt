package com.venice.memscan

import java.io.IOException

class Scanner(private val shell: RootShell) {

    fun attach(pkg: String): Int {
        val r = shell.cmd("pid $pkg")
        if (!r.startsWith("OK ")) throw IOException(r.removePrefix("ERR ").trim())
        return r.substring(3).trim().toInt()
    }

    fun scanFirst(type: Int, bits: Long): Long {
        val r = shell.cmd("scan1 $type $bits")
        if (!r.startsWith("OK ")) throw IOException(r.removePrefix("ERR ").trim())
        return r.substring(3).trim().toLong()
    }

    fun scanNext(type: Int, pred: Int, bits: Long): Long {
        val r = shell.cmd("next $type $pred $bits")
        if (!r.startsWith("OK ")) throw IOException(r.removePrefix("ERR ").trim())
        return r.substring(3).trim().toLong()
    }

    fun results(start: Int, count: Int, type: Int): List<Pair<Long, Long>> {
        val lines = shell.cmdLines("results $start $count $type")
        return lines.mapNotNull { l ->
            val parts = l.trim().split(" ")
            if (parts.size != 2) return@mapNotNull null
            val a = parts[0].toLongOrNull(16) ?: return@mapNotNull null
            val v = parts[1].toLongOrNull() ?: return@mapNotNull null
            a to v
        }
    }

    fun write(addr: Long, type: Int, bits: Long) {
        val r = shell.cmd("write ${addr.toString(16)} $type $bits")
        if (!r.startsWith("OK")) throw IOException(r.removePrefix("ERR ").trim())
    }

    fun freeze(addr: Long, type: Int, bits: Long) {
        val r = shell.cmd("freeze ${addr.toString(16)} $type $bits")
        if (!r.startsWith("OK")) throw IOException(r.removePrefix("ERR ").trim())
    }

    fun unfreeze(addr: Long) {
        val r = shell.cmd("unfreeze ${addr.toString(16)}")
        if (!r.startsWith("OK")) throw IOException(r.removePrefix("ERR ").trim())
    }

    fun clear() {
        shell.cmd("clear")
    }

    fun findString(value: String): List<Long> = findPattern("findstr", value)

    fun findAob(pattern: String): List<Long> = findPattern("findaob", pattern)

    private fun findPattern(command: String, value: String): List<Long> {
        val safe = value.replace("\n", " ").replace("\r", " ")
        return shell.cmdLines("$command $safe").mapNotNull { it.trim().toLongOrNull(16) }
    }

    fun findPointersTo(address: Long): List<Long> {
        return shell.cmdLines("ptrscan ${address.toString(16)}").mapNotNull { it.trim().toLongOrNull(16) }
    }

    fun inspectPointer(address: Long): Pair<Long, Boolean> {
        val r = shell.cmd("ptr ${address.toString(16)}")
        if (!r.startsWith("OK ")) throw IOException(r.removePrefix("ERR ").trim())
        val p = r.split(Regex("\\s+"))
        return (p[1].toLong(16)) to (p.getOrNull(2) == "mapped")
    }

    fun readHex(address: Long, length: Int): String {
        val r = shell.cmd("readhex ${address.toString(16)} $length")
        if (!r.startsWith("OK ")) throw IOException(r.removePrefix("ERR ").trim())
        return r.substring(3).trim()
    }

    fun writeHex(address: Long, hex: String) {
        val normalized = hex.filterNot { it.isWhitespace() }
        if (normalized.isEmpty() || normalized.length > 128 || normalized.length % 2 != 0 || !normalized.all { it.isDigit() || it.lowercaseChar() in 'a'..'f' }) {
            throw IOException("Enter 1..64 bytes as hexadecimal pairs")
        }
        val r = shell.cmd("writehex ${address.toString(16)} $normalized")
        if (!r.startsWith("OK")) throw IOException(r.removePrefix("ERR ").trim())
    }

    fun count(): Long {
        val r = shell.cmd("count")
        return if (r.startsWith("OK ")) r.substring(3).trim().toLongOrNull() ?: 0L else 0L
    }

    companion object {
        const val TYPE_I8 = 0
        const val TYPE_I16 = 1
        const val TYPE_I32 = 2
        const val TYPE_I64 = 3
        const val TYPE_F32 = 4
        const val TYPE_F64 = 5

        const val PRED_EQ = 0
        const val PRED_NE = 1
        const val PRED_GT = 2
        const val PRED_LT = 3
        const val PRED_CHANGED = 4
        const val PRED_UNCHANGED = 5
        const val PRED_INC = 6
        const val PRED_DEC = 7

        val TYPE_LABELS = arrayOf("byte", "word", "dword", "qword", "float", "double")
        val PRED_LABELS = arrayOf("equals", "not equal", "greater", "less", "changed", "unchanged", "increased", "decreased")

        fun needsValue(pred: Int): Boolean = pred <= PRED_LT

        fun parseBits(type: Int, text: String): Long {
            val s = text.trim()
            if (s.isEmpty()) throw IOException("value required")
            return when (type) {
                TYPE_F32 -> java.lang.Float.floatToRawIntBits(s.toFloat()).toLong()
                TYPE_F64 -> java.lang.Double.doubleToRawLongBits(s.toDouble())
                else -> s.toLong()
            }
        }

        fun formatValue(type: Int, bits: Long): String = when (type) {
            TYPE_F32 -> java.lang.Float.intBitsToFloat(bits.toInt()).toString()
            TYPE_F64 -> java.lang.Double.longBitsToDouble(bits).toString()
            TYPE_I8 -> (bits.toByte()).toString()
            TYPE_I16 -> (bits.toShort()).toString()
            TYPE_I32 -> (bits.toInt()).toString()
            else -> bits.toString()
        }
    }
}
