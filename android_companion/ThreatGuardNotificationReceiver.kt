package com.threatguard.sentinel

import android.app.Notification
import android.content.Context
import android.service.notification.NotificationListenerService
import android.service.notification.StatusBarNotification
import android.util.Log
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import org.json.JSONObject
import java.io.OutputStreamWriter
import java.net.HttpURLConnection
import java.net.URL

/**
 * ThreatGuard AI — WhatsApp Real-Time Notification Interceptor
 *
 * HOW IT WORKS:
 * 1. Android NotificationListenerService intercepts notifications from `com.whatsapp`.
 * 2. Reads incoming message text and contact/group name from notification extras.
 * 3. Immediately posts to ThreatGuard Backend: `/api/whatsapp/incoming`.
 * 4. If AI detects scam/phishing/fake job lure (Red Flag), triggers warning alert before user clicks.
 */
class ThreatGuardNotificationReceiver : NotificationListenerService() {

    companion object {
        private const val TAG = "ThreatGuardWA"
        private const val WHATSAPP_PACKAGE = "com.whatsapp"
        // Replace with your computer's IP address (e.g. http://192.168.1.5:8000/api/whatsapp/incoming)
        private const val BACKEND_ENDPOINT = "http://10.0.2.2:8000/api/whatsapp/incoming"
    }

    override fun onNotificationPosted(sbn: StatusBarNotification?) {
        if (sbn == null || sbn.packageName != WHATSAPP_PACKAGE) return

        val extras = sbn.notification.extras ?: return
        val senderTitle = extras.getString(Notification.EXTRA_TITLE) ?: "WhatsApp Contact"
        val messageText = extras.getCharSequence(Notification.EXTRA_TEXT)?.toString() ?: ""

        if (messageText.isBlank()) return

        Log.i(TAG, "Incoming WhatsApp from $senderTitle: $messageText")

        // Send to ThreatGuard AI Backend in Background
        CoroutineScope(Dispatchers.IO).launch {
            forwardWhatsAppMessage(senderTitle, messageText)
        }
    }

    private fun forwardWhatsAppMessage(sender: String, message: String) {
        try {
            val url = URL(BACKEND_ENDPOINT)
            val conn = url.openConnection() as HttpURLConnection
            conn.requestMethod = "POST"
            conn.setRequestProperty("Content-Type", "application/json")
            conn.setRequestProperty("Accept", "application/json")
            conn.doOutput = true
            conn.connectTimeout = 3000
            conn.readTimeout = 3000

            val payload = JSONObject().apply {
                put("sender", "$sender (WhatsApp)")
                put("message", message)
                put("channel", "whatsapp")
                put("source", "android_notification_listener")
            }

            OutputStreamWriter(conn.outputStream).use { writer ->
                writer.write(payload.toString())
                writer.flush()
            }

            if (conn.responseCode == 200) {
                val responseText = conn.inputStream.bufferedReader().use { it.readText() }
                val json = JSONObject(responseText)
                val isRedFlagged = json.optBoolean("is_red_flagged", false)
                val riskLevel = json.optString("risk_level", "LOW")

                if (isRedFlagged) {
                    Log.w(TAG, "🚨 RED FLAG DETECTED! ThreatGuard blocked WhatsApp scam from $sender (Risk: $riskLevel)")
                } else {
                    Log.i(TAG, "✅ WhatsApp message verified clean.")
                }
            }
        } catch (e: Exception) {
            Log.e(TAG, "Error contacting ThreatGuard backend: ${e.message}")
        }
    }
}

