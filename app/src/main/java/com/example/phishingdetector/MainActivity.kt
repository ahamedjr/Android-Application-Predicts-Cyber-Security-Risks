package com.example.phishingdetector

import android.os.Bundle
import android.widget.Toast
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            PhishingDetectorApp()
        }
    }
}

@Composable
fun PhishingDetectorApp() {
    var url by remember { mutableStateOf("") }
    var result by remember { mutableStateOf<URLAnalysis?>(null) }
    val context = LocalContext.current

    Column(
        modifier = Modifier
            .fillMaxSize()
            .background(Color(0xFFF5F5F5))
            .padding(24.dp),
        verticalArrangement = Arrangement.Center,
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        Text(
            "Phishing Detector",
            fontSize = 28.sp,
            color = Color(0xFF1A237E)
        )
        Spacer(modifier = Modifier.height(8.dp))
        Text("Powerful URL Security Checker by JR", fontSize = 14.sp, color = Color.Gray)
        Spacer(modifier = Modifier.height(32.dp))
        OutlinedTextField(
            value = url,
            onValueChange = { url = it },
            label = { Text("Enter URL to Check") },
            singleLine = true,
            modifier = Modifier.fillMaxWidth(),
            keyboardOptions = KeyboardOptions.Default.copy(keyboardType = KeyboardType.Uri)
        )
        Spacer(modifier = Modifier.height(16.dp))
        Button(
            onClick = {
                if (url.isBlank()) {
                    Toast.makeText(context, "Please enter a URL", Toast.LENGTH_SHORT).show()
                } else {
                    result = analyzeURL(url)
                }
            },
            modifier = Modifier.fillMaxWidth(),
            colors = ButtonDefaults.buttonColors(backgroundColor = Color(0xFF1A237E))
        ) {
            Text("Scan URL", color = Color.White)
        }
        Spacer(modifier = Modifier.height(24.dp))
        result?.let { ShowResultCard(it) }
    }
}

data class URLAnalysis(val riskScore: Int, val category: String, val threats: List<String>)

fun analyzeURL(url: String): URLAnalysis {
    var riskScore = 0
    val threats = mutableListOf<String>()
    if (!url.startsWith("https://")) {
        riskScore += 20
        threats.add("❌ No HTTPS encryption")
    } else {
        threats.add("✅ HTTPS encryption enabled")
    }
    if (url.length > 75) {
        riskScore += 15
        threats.add("⚠️ Unusually long URL")
    }
    val ipPattern = Regex("""\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}""")
    if (ipPattern.containsMatchIn(url)) {
        riskScore += 25
        threats.add("⚠️ Uses IP address instead of domain")
    }
    val suspiciousWords = listOf(
        "verify", "account", "login", "secure", "update",
        "confirm", "banking", "paypal", "signin", "ebay"
    )
    val foundWords = suspiciousWords.filter { url.lowercase().contains(it) }
    if (foundWords.isNotEmpty()) {
        riskScore += foundWords.size * 10
        threats.add("⚠️ Suspicious keywords: ${foundWords.joinToString(", ")}")
    }
    if (url.contains("@")) {
        riskScore += 30
        threats.add("🚨 Contains @ symbol (domain masking)")
    }
    val dotCount = url.count { it == '.' }
    if (dotCount > 4) {
        riskScore += 10
        threats.add("⚠️ Excessive subdomains ($dotCount dots)")
    }
    if (url.count { it == '-' } > 4) {
        riskScore += 10
        threats.add("⚠️ Suspicious number of dashes")
    }
    val shorteners = listOf("bit.ly", "tinyurl", "goo.gl", "ow.ly", "t.co")
    if (shorteners.any { url.contains(it) }) {
        riskScore += 15
        threats.add("⚠️ URL shortener detected")
    }
    riskScore = riskScore.coerceAtMost(100)
    val category = when {
        riskScore < 30 -> "Safe"
        riskScore < 60 -> "Suspicious"
        else -> "Dangerous"
    }
    return URLAnalysis(riskScore, category, threats)
}

@Composable
fun ShowResultCard(analysis: URLAnalysis) {
    val color = when (analysis.category) {
        "Safe" -> Color(0xFF4CAF50)
        "Suspicious" -> Color(0xFFFF9800)
        else -> Color(0xFFF44336)
    }
    Card(
        backgroundColor = Color.White,
        elevation = 8.dp,
        modifier = Modifier.fillMaxWidth()
    ) {
        Column(
            Modifier.padding(20.dp)
        ) {
            Text(
                when (analysis.category) {
                    "Safe" -> "✅ URL Appears Safe"
                    "Suspicious" -> "⚠️ Suspicious URL"
                    else -> "🚨 DANGEROUS - Potential Phishing!"
                },
                fontSize = 20.sp,
                color = color
            )
            Spacer(modifier = Modifier.height(8.dp))
            Text("Risk Score: ${analysis.riskScore}/100", fontSize = 16.sp)
            Spacer(modifier = Modifier.height(8.dp))
            LinearProgressIndicator(
                progress = analysis.riskScore / 100f,
                color = color,
                backgroundColor = Color(0x22000000),
                modifier = Modifier.height(10.dp).fillMaxWidth()
            )
            Spacer(modifier = Modifier.height(12.dp))
            for (threat in analysis.threats) {
                Text(threat, fontSize = 14.sp, color = Color.Gray)
            }
        }
    }
}
