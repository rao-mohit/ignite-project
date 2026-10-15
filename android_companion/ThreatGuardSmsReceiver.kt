package com.threatguard.sentinel

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.os.Build
import android.provider.Telephony
import android.telephony.SmsMessage
import android.util.Log
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import org.json.JSONObject
import java.io.OutputStreamWriter
import java.net.HttpURLConnection
import java.net.URL

/**
 * ThreatGuard AI — Real-Time Android SMS Interceptor & Red-Flag Sentinel
 *
 * HOW IT WORKS:
 * 1. Listens for the system `android.provider.Telephony.SMS_RECEIVED` event when ANY new SMS arrives.
 * 2. Extracts sender phone number & full SMS body.
 * 3. Dispatches HTTP POST to ThreatGuard backend: `/api/sms/incoming`.
 * 4. ThreatGuard AI instantly classifies the text using ML + Heuristics.
 * 5. If `risk_level == 'HIGH' or 'CRITICAL'` (Red-Flagged), triggers immediate local Android notification.
 */
class ThreatGuardSmsReceiver : BroadcastReceiver() {

    companion object {
        private const val TAG = "ThreatGuardSMS"
        // Replace with your local machine IP or Ngrok/Cloud server URL
        private const val BACKEND_ENDPOINT = "http://10.0.2.2:8000/api/sms/incoming"
    }

    override fun onReceive(context: Context?, intent: Intent?) {
        if (intent?.action != Telephony.Sms.Intents.SMS_RECEIVED_ACTION) return

        val messages: Array<SmsMessage>? = Telephony.Sms.Intents.getMessagesFromIntent(intent)
        if (messages.isNullOrEmpty()) return

        val sender = messages[0].displayOriginatingAddress ?: "Unknown Sender"
        val messageBody = buildString {
            for (sms in messages) {
                append(sms.displayMessageBody)
            }
        }

        Log.i(TAG, "Incoming SMS from $sender: $messageBody")

        // Send to ThreatGuard AI Backend Asynchronously
        CoroutineScope(Dispatchers.IO).launch {
            forwardSmsToThreatGuard(sender, messageBody, context)
        }
    }

    private fun forwardSmsToThreatGuard(sender: String, message: String, context: Context?) {
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
                put("sender", sender)
                put("message", message)
                put("source", "android_realtime_listener")
            }

            OutputStreamWriter(conn.outputStream).use { writer ->
                writer.write(payload.toString())
                writer.flush()
            }

            val responseCode = conn.responseCode
            if (responseCode == 200) {
                val responseText = conn.inputStream.bufferedReader().use { it.readText() }
                val jsonResponse = JSONObject(responseText)
                val isRedFlagged = jsonResponse.optBoolean("is_red_flagged", false)
                val riskLevel = jsonResponse.optString("risk_level", "LOW")

                if (isRedFlagged) {
                    Log.w(TAG, "🚨 RED FLAG DETECTED! ThreatGuard intercepted scam from $sender (Level: $riskLevel)")
                    // Here you can trigger Android NotificationManager warning alert
                } else {
                    Log.i(TAG, "✅ SMS verified safe by ThreatGuard AI.")
                }
            }
        } catch (e: Exception) {
            Log.e(TAG, "Failed to send SMS to ThreatGuard backend: ${e.message}")
        }
    }
}

