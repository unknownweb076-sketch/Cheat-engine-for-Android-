package com.venice.memscan

import android.app.AlertDialog
import android.os.Bundle
import android.content.Intent
import android.net.Uri
import android.provider.Settings
import android.text.InputType
import android.widget.ArrayAdapter
import android.widget.EditText
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import com.venice.memscan.databinding.ActivityMainBinding

class MainActivity : AppCompatActivity() {

    private lateinit var b: ActivityMainBinding
    private val shell = RootShell()
    private lateinit var scanner: Scanner
    private lateinit var adapter: ResultAdapter

    private var targetPkg: String? = null
    private var type = Scanner.TYPE_I32
    private var scanType: Int? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        b = ActivityMainBinding.inflate(layoutInflater)
        setContentView(b.root)

        scanner = Scanner(shell)
        adapter = ResultAdapter(
            onWrite = { addr -> askWrite(addr) },
            onFreeze = { addr, on -> toggleFreeze(addr, on) }
        )
        b.list.layoutManager = LinearLayoutManager(this)
        b.list.adapter = adapter

        b.typeSpinner.adapter = ArrayAdapter(this, android.R.layout.simple_spinner_dropdown_item, Scanner.TYPE_LABELS)
        b.typeSpinner.setSelection(Scanner.TYPE_I32)
        b.predSpinner.adapter = ArrayAdapter(this, android.R.layout.simple_spinner_dropdown_item, Scanner.PRED_LABELS)
        b.predSpinner.setSelection(Scanner.PRED_CHANGED)

        b.pickBtn.text = "Choose target app"
        b.pickBtn.setOnClickListener { showTargetPicker() }
        b.firstBtn.setOnClickListener { doFirst() }
        b.nextBtn.setOnClickListener { doNext() }
        b.clearBtn.setOnClickListener { doClear() }
        b.stringBtn.setOnClickListener { askPattern("Find UTF-8 string", "", false) }
        b.aobBtn.setOnClickListener { askPattern("Find AOB (example: 2A ?? FF)", "", true) }
        b.pointerBtn.setOnClickListener { askPointer() }
        b.overlayBtn.setOnClickListener { toggleOverlay() }

        b.typeSpinner.onItemSelectedListener = SimpleSelect {
            val locked = scanType
            if (locked != null && it != locked) {
                toast("Clear the current scan before changing data type")
                b.typeSpinner.setSelection(locked)
            } else type = it
        }

        startRoot()
    }

    private fun startRoot() {
        val helper = java.io.File(applicationInfo.nativeLibraryDir, "libscanhelper.so").absolutePath
        status("Requesting root...")
        Thread {
            val ok = shell.start(helper)
            runOnUiThread {
                if (ok) status("Root ready. Select an app you own or are authorized to test offline.")
                else status("Root failed. Is Magisk installed and granted?")
            }
        }.start()
    }

    private fun status(s: String) {
        b.statusText.text = s
    }

    private fun requireReady(): Boolean {
        if (!shell.alive) { toast("Root shell not running"); return false }
        if (targetPkg == null) { toast("Select a target app first"); return false }
        return true
    }

    private fun showTargetPicker() {
        val apps = packageManager.getInstalledApplications(0)
            .filter { packageManager.getLaunchIntentForPackage(it.packageName) != null }
            .sortedBy { packageManager.getApplicationLabel(it).toString().lowercase() }
        if (apps.isEmpty()) { toast("No launchable apps found"); return }
        val labels = apps.map {
            "${packageManager.getApplicationLabel(it)}\n${it.packageName}"
        }.toTypedArray()
        AlertDialog.Builder(this)
            .setTitle("Choose an installed app")
            .setItems(labels) { _, which ->
                val app = apps[which]
                selectApp(app.packageName, packageManager.getApplicationLabel(app).toString())
            }
            .setNegativeButton("Cancel", null)
            .show()
    }

    private fun selectApp(pkg: String, label: String) {
        Thread {
            try {
                val pid = scanner.attach(pkg)
                runOnUiThread {
                    targetPkg = pkg
                    scanType = null
                    adapter.submit(emptyList())
                    b.targetText.text = "$label  (pid $pid)\n$pkg"
                    b.countText.text = "Results: 0"
                    status("Attached")
                }
            } catch (e: Exception) {
                runOnUiThread { toast("Attach failed: ${e.message}") }
            }
        }.start()
    }

    private fun doFirst() {
        if (!requireReady()) return
        val selectedType = type
        val bits = try { Scanner.parseBits(selectedType, b.valueInput.text.toString()) } catch (e: Exception) {
            toast("Enter a valid value"); return
        }
        status("Scanning...")
        Thread {
            try {
                val n = scanner.scanFirst(selectedType, bits)
                runOnUiThread {
                    scanType = selectedType
                    adapter.type = selectedType
                    status("First scan done")
                    b.countText.text = "Results: $n"
                    loadResults()
                }
            } catch (e: Exception) {
                runOnUiThread { status("Scan failed: ${e.message}") }
            }
        }.start()
    }

    private fun doNext() {
        if (!requireReady()) return
        if (scanType != null && scanType != type) { toast("Changing data type clears the current scan. Run First scan again."); return }
        val selectedType = scanType ?: type
        val pred = b.predSpinner.selectedItemPosition
        val bits = if (Scanner.needsValue(pred)) {
            try { Scanner.parseBits(selectedType, b.valueInput.text.toString()) } catch (e: Exception) {
                toast("This filter needs a value"); return
            }
        } else 0L

        status("Filtering...")
        Thread {
            try {
                val n = scanner.scanNext(selectedType, pred, bits)
                runOnUiThread {
                    status("Filter applied")
                    b.countText.text = "Results: $n"
                    loadResults()
                }
            } catch (e: Exception) {
                runOnUiThread { status("Filter failed: ${e.message}") }
            }
        }.start()
    }

    private fun loadResults() {
        Thread {
            val rows = try { scanner.results(0, 500, scanType ?: type) } catch (e: Exception) { emptyList() }
            runOnUiThread {
                adapter.type = scanType ?: type
                adapter.submit(rows)
            }
        }.start()
    }

    private fun askWrite(addr: Long) {
        val input = EditText(this)
        input.inputType = InputType.TYPE_CLASS_NUMBER or InputType.TYPE_NUMBER_FLAG_SIGNED or
            InputType.TYPE_NUMBER_FLAG_DECIMAL
        AlertDialog.Builder(this)
            .setTitle("Write 0x" + addr.toString(16))
            .setView(input)
            .setPositiveButton("Write") { _, _ ->
                val writeType = scanType ?: type
                val bits = try { Scanner.parseBits(writeType, input.text.toString()) } catch (e: Exception) {
                    toast("Invalid value"); return@setPositiveButton
                }
                Thread {
                    try {
                        scanner.write(addr, writeType, bits)
                        runOnUiThread { loadResults() }
                    } catch (e: Exception) {
                        runOnUiThread { toast("Write failed: ${e.message}") }
                    }
                }.start()
            }
            .setNegativeButton("Cancel", null)
            .show()
    }

    private fun toggleFreeze(addr: Long, on: Boolean) {
        Thread {
            try {
                if (on) {
                    val rows = scanner.results(0, 500, scanType ?: type).firstOrNull { it.first == addr }
                        ?: throw java.io.IOException("Result is no longer available; refresh the scan")
                    scanner.freeze(addr, scanType ?: type, rows.second)
                } else {
                    scanner.unfreeze(addr)
                }
            } catch (e: Exception) {
                runOnUiThread { toast("Freeze failed: ${e.message}") }
            }
        }.start()
    }

    private fun askPattern(title: String, initial: String, aob: Boolean) {
        val input = EditText(this).apply { setText(initial); hint = if (aob) "48 8B ?? 24" else "text to locate" }
        AlertDialog.Builder(this).setTitle(title).setView(input)
            .setPositiveButton("Scan") { _, _ ->
                if (!requireReady()) return@setPositiveButton
                val query = input.text.toString()
                if (query.isBlank() || query.contains('\n') || query.contains('\r')) { toast("Enter a valid pattern"); return@setPositiveButton }
                status("Searching memory...")
                Thread {
                    try {
                        val hits = if (aob) scanner.findAob(query) else scanner.findString(query)
                        runOnUiThread {
                            status("Pattern scan complete: ${hits.size} result(s)")
                            if (hits.isEmpty()) {
                                AlertDialog.Builder(this).setTitle("Matches").setMessage("No matches found")
                                    .setPositiveButton("OK", null).show()
                            } else {
                                val shown = hits.take(100)
                                val labels = shown.map { "0x${it.toString(16)}  ·  edit bytes" }.toTypedArray()
                                AlertDialog.Builder(this).setTitle("Matches — tap an address to edit bytes")
                                    .setItems(labels) { _, which -> askHexEdit(shown[which]) }
                                    .setNegativeButton("Close", null).show()
                            }
                        }
                    } catch (e: Exception) { runOnUiThread { status("Pattern scan failed: ${e.message}") } }
                }.start()
            }.setNegativeButton("Cancel", null).show()
    }

    private fun askHexEdit(address: Long) {
        Thread {
            try {
                val current = scanner.readHex(address, 16)
                runOnUiThread {
                    val input = EditText(this).apply {
                        setText(current.chunked(2).joinToString(" "))
                        hint = "AA BB CC DD"
                        inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_FLAG_CAP_CHARACTERS
                    }
                    AlertDialog.Builder(this)
                        .setTitle("Hex editor · 0x${address.toString(16)}")
                        .setMessage("Edit up to 64 bytes. Use hexadecimal byte pairs.")
                        .setView(input)
                        .setPositiveButton("Write bytes") { _, _ ->
                            Thread {
                                try {
                                    scanner.writeHex(address, input.text.toString())
                                    runOnUiThread { toast("Memory bytes written") }
                                } catch (e: Exception) {
                                    runOnUiThread { toast("Write failed: ${e.message}") }
                                }
                            }.start()
                        }
                        .setNegativeButton("Cancel", null)
                        .show()
                }
            } catch (e: Exception) {
                runOnUiThread { toast("Cannot read address: ${e.message}") }
            }
        }.start()
    }

    private fun askPointer() {
        val input = EditText(this).apply { hint = "Address in hex (e.g. 7abc1234)" }
        AlertDialog.Builder(this).setTitle("Inspect pointer at address").setView(input)
            .setPositiveButton("Inspect") { _, _ ->
                if (!requireReady()) return@setPositiveButton
                val address = input.text.toString().trim().removePrefix("0x").toLongOrNull(16)
                if (address == null) { toast("Enter a valid hexadecimal address"); return@setPositiveButton }
                Thread {
                    try {
                        val (value, mapped) = scanner.inspectPointer(address)
                        runOnUiThread { AlertDialog.Builder(this).setTitle("Pointer inspection")
                            .setMessage("[0x${address.toString(16)}] → 0x${value.toString(16)}\nTarget region: ${if (mapped) "mapped" else "not mapped"}")
                            .setPositiveButton("Find references") { _, _ ->
                                status("Scanning pointers...")
                                Thread {
                                    try {
                                        val refs = scanner.findPointersTo(value)
                                        runOnUiThread {
                                            status("Pointer scan complete: ${refs.size} result(s)")
                                            if (refs.isEmpty()) {
                                                AlertDialog.Builder(this).setTitle("Pointer references").setMessage("No references found")
                                                    .setPositiveButton("OK", null).show()
                                            } else {
                                                val shown = refs.take(100)
                                                AlertDialog.Builder(this).setTitle("References — tap to inspect bytes")
                                                    .setItems(shown.map { "0x${it.toString(16)}" }.toTypedArray()) { _, which -> askHexEdit(shown[which]) }
                                                    .setNegativeButton("Close", null).show()
                                            }
                                        }
                                    } catch (e: Exception) { runOnUiThread { toast("Pointer scan failed: ${e.message}") } }
                                }.start()
                            }.setNegativeButton("Close", null).show() }
                    } catch (e: Exception) { runOnUiThread { toast("Pointer inspection failed: ${e.message}") } }
                }.start()
            }.setNegativeButton("Cancel", null).show()
    }

    private fun toggleOverlay() {
        if (!Settings.canDrawOverlays(this)) {
            startActivity(Intent(Settings.ACTION_MANAGE_OVERLAY_PERMISSION, Uri.parse("package:$packageName")))
            toast("Allow display over other apps, then tap Overlay again")
            return
        }
        val intent = Intent(this, OverlayService::class.java)
        if (b.overlayBtn.text.toString() == "Overlay") {
            startService(intent); b.overlayBtn.text = "Stop overlay"
        } else {
            stopService(intent); b.overlayBtn.text = "Overlay"
        }
    }

    private fun doClear() {
        Thread {
            try { scanner.clear() } catch (_: Exception) {}
            runOnUiThread {
                scanType = null
                adapter.submit(emptyList())
                b.countText.text = "Results: 0"
                status("Cleared")
            }
        }.start()
    }

    private fun toast(s: String) = Toast.makeText(this, s, Toast.LENGTH_SHORT).show()

    override fun onDestroy() {
        shell.stop()
        super.onDestroy()
    }

    private class SimpleSelect(val onPick: (Int) -> Unit) : android.widget.AdapterView.OnItemSelectedListener {
        override fun onItemSelected(p: android.widget.AdapterView<*>?, v: android.view.View?, pos: Int, id: Long) = onPick(pos)
        override fun onNothingSelected(p: android.widget.AdapterView<*>?) {}
    }
}
