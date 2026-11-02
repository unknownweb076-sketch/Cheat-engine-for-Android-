package com.venice.memscan

import android.app.Service
import android.content.Intent
import android.graphics.Color
import android.graphics.PixelFormat
import android.graphics.Typeface
import android.os.IBinder
import android.provider.Settings
import android.view.Gravity
import android.view.WindowManager
import android.widget.TextView

class OverlayService : Service() {
    private var windowManager: WindowManager? = null
    private var chip: TextView? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (!Settings.canDrawOverlays(this)) { stopSelf(); return START_NOT_STICKY }
        if (chip != null) return START_STICKY
        windowManager = getSystemService(WINDOW_SERVICE) as WindowManager
        val view = TextView(this).apply {
            text = "  MemScan  "
            textSize = 14f
            setTextColor(Color.WHITE)
            setBackgroundColor(0xDD20242A.toInt())
            setPadding(18, 12, 18, 12)
            typeface = Typeface.DEFAULT_BOLD
            setOnClickListener {
                val launch = packageManager.getLaunchIntentForPackage(packageName)
                launch?.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                if (launch != null) startActivity(launch)
            }
            setOnLongClickListener { stopSelf(); true }
        }
        val params = WindowManager.LayoutParams(
            WindowManager.LayoutParams.WRAP_CONTENT,
            WindowManager.LayoutParams.WRAP_CONTENT,
            WindowManager.LayoutParams.TYPE_APPLICATION_OVERLAY,
            WindowManager.LayoutParams.FLAG_NOT_FOCUSABLE or WindowManager.LayoutParams.FLAG_LAYOUT_IN_SCREEN,
            PixelFormat.TRANSLUCENT
        ).apply { gravity = Gravity.TOP or Gravity.END; x = 24; y = 180 }
        windowManager?.addView(view, params)
        chip = view
        return START_STICKY
    }

    override fun onDestroy() {
        chip?.let { try { windowManager?.removeView(it) } catch (_: Exception) {} }
        chip = null
        super.onDestroy()
    }

    override fun onBind(intent: Intent?): IBinder? = null
}
