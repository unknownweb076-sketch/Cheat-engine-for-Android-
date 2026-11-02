package com.venice.memscan

import java.io.BufferedReader
import java.io.BufferedWriter
import java.io.IOException
import java.io.InputStreamReader
import java.io.OutputStreamWriter
import java.util.concurrent.locks.ReentrantLock
import kotlin.concurrent.withLock

class RootShell {

    private var proc: Process? = null
    private var out: BufferedWriter? = null
    private var inp: BufferedReader? = null
    private val lock = ReentrantLock()

    val alive: Boolean get() = proc?.isAlive == true

    fun start(helperPath: String): Boolean {
        stop()
        return try {
            val p = Runtime.getRuntime().exec(arrayOf("su"))
            proc = p
            out = BufferedWriter(OutputStreamWriter(p.outputStream))
            inp = BufferedReader(InputStreamReader(p.inputStream))
            send("chmod 755 $helperPath")
            send("exec $helperPath")
            val hello = inp!!.readLine()
            hello == "READY"
        } catch (e: Exception) {
            stop()
            false
        }
    }

    fun stop() {
        try { out?.write("quit\n"); out?.flush() } catch (_: Exception) {}
        try { proc?.destroy() } catch (_: Exception) {}
        proc = null
        out = null
        inp = null
    }

    private fun send(line: String) {
        out!!.write(line + "\n")
        out!!.flush()
    }

    fun cmd(line: String): String = lock.withLock {
        val o = out ?: throw IOException("shell not started")
        val i = inp ?: throw IOException("shell not started")
        o.write(line + "\n")
        o.flush()
        i.readLine() ?: throw IOException("root shell died")
    }

    fun cmdLines(line: String): List<String> = lock.withLock {
        val o = out ?: throw IOException("shell not started")
        val i = inp ?: throw IOException("shell not started")
        o.write(line + "\n")
        o.flush()
        val res = ArrayList<String>()
        while (true) {
            val l = i.readLine() ?: break
            if (l == "END") break
            res.add(l)
        }
        res
    }
}
