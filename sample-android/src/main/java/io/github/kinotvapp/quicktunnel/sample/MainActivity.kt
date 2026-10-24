package io.github.kinotvapp.quicktunnel.sample

import android.app.Activity
import android.content.Intent
import android.os.Build
import android.os.Bundle
import android.widget.TextView

class MainActivity : Activity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(TextView(this).apply { text = "QT test: tunnel service started (see logcat tag QT)"; textSize = 18f; setPadding(48, 96, 48, 48) })
        val service = Intent(this, TunnelService::class.java).putExtra("policy", intent.getStringExtra("policy"))
        if (Build.VERSION.SDK_INT >= 26) startForegroundService(service) else startService(service) // 26+ only
    }
}
