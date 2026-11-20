package com.llmsecurityscanner.presentation.settings

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.llmsecurityscanner.presentation.components.CyberCard
import com.llmsecurityscanner.presentation.theme.*

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SettingsScreen(
    viewModel: SettingsViewModel,
    onBack: () -> Unit
) {
    val state by viewModel.uiState.collectAsState()
    var urlInput by remember(state.baseUrl) { mutableStateOf(state.baseUrl) }
    var tokenInput by remember(state.authToken) { mutableStateOf(state.authToken) }
    var userIdInput by remember(state.userId) { mutableStateOf(state.userId) }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Settings & Environment", fontWeight = FontWeight.Bold, fontSize = 18.sp) },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.Default.ArrowBack, contentDescription = "Back", tint = TextPrimary)
                    }
                },
                colors = TopAppBarDefaults.topAppBarColors(containerColor = CyberSurface)
            )
        },
        containerColor = CyberBg
    ) { padding ->
        LazyColumn(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp)
        ) {
            // Backend Server Configuration
            item {
                CyberCard(borderColor = CyberCyan) {
                    Text(text = "BACKEND SERVER CONFIGURATION", fontSize = 11.sp, fontWeight = FontWeight.SemiBold, color = TextMuted)
                    Spacer(modifier = Modifier.height(8.dp))
                    OutlinedTextField(
                        value = urlInput,
                        onValueChange = {
                            urlInput = it
                            viewModel.updateBaseUrl(it)
                        },
                        label = { Text("FastAPI Server Base URL") },
                        colors = OutlinedTextFieldDefaults.colors(
                            focusedTextColor = TextPrimary,
                            unfocusedTextColor = TextPrimary,
                            focusedBorderColor = CyberCyan,
                            unfocusedBorderColor = CyberSurfaceBorder
                        ),
                        modifier = Modifier.fillMaxWidth()
                    )

                    Spacer(modifier = Modifier.height(10.dp))

                    // Preset buttons
                    Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        Button(
                            onClick = {
                                val emulatorUrl = "http://10.0.2.2:8000/"
                                urlInput = emulatorUrl
                                viewModel.updateBaseUrl(emulatorUrl)
                            },
                            colors = ButtonDefaults.buttonColors(containerColor = CyberSurfaceBorder),
                            modifier = Modifier.weight(1f)
                        ) {
                            Text("Emulator (10.0.2.2)", fontSize = 11.sp, color = TextPrimary)
                        }
                        Button(
                            onClick = { viewModel.testConnection() },
                            colors = ButtonDefaults.buttonColors(containerColor = CyberCyan, contentColor = CyberBg),
                            modifier = Modifier.weight(1f),
                            enabled = !state.isTestingConnection
                        ) {
                            if (state.isTestingConnection) {
                                CircularProgressIndicator(modifier = Modifier.size(16.dp), color = CyberBg, strokeWidth = 2.dp)
                            } else {
                                Text("Ping Health", fontSize = 11.sp, fontWeight = FontWeight.Bold)
                            }
                        }
                    }

                    if (state.connectionStatus != null) {
                        Spacer(modifier = Modifier.height(10.dp))
                        val isOk = state.isConnected == true
                        Box(
                            modifier = Modifier
                                .fillMaxWidth()
                                .background(
                                    if (isOk) SeverityLow.copy(alpha = 0.15f) else SeverityCritical.copy(alpha = 0.15f),
                                    RoundedCornerShape(6.dp)
                                )
                                .border(1.dp, if (isOk) SeverityLow else SeverityCritical, RoundedCornerShape(6.dp))
                                .padding(8.dp)
                        ) {
                            Text(
                                text = state.connectionStatus ?: "",
                                fontSize = 12.sp,
                                color = if (isOk) SeverityLow else SeverityCritical,
                                fontWeight = FontWeight.SemiBold
                            )
                        }
                    }
                }
            }

            // Secure Token & Identity
            item {
                CyberCard {
                    Text(text = "AUTHENTICATION & IDENTITY", fontSize = 11.sp, fontWeight = FontWeight.SemiBold, color = TextMuted)
                    Spacer(modifier = Modifier.height(8.dp))
                    Text(
                        text = "Tokens are stored in Android Keystore backed EncryptedSharedPreferences.",
                        fontSize = 12.sp,
                        color = TextSecondary
                    )
                    Spacer(modifier = Modifier.height(8.dp))

                    OutlinedTextField(
                        value = tokenInput,
                        onValueChange = {
                            tokenInput = it
                            viewModel.updateAuthToken(it)
                        },
                        label = { Text("Bearer JWT Token (Optional)") },
                        colors = OutlinedTextFieldDefaults.colors(
                            focusedTextColor = TextPrimary,
                            unfocusedTextColor = TextPrimary,
                            focusedBorderColor = CyberCyan,
                            unfocusedBorderColor = CyberSurfaceBorder
                        ),
                        modifier = Modifier.fillMaxWidth()
                    )

                    Spacer(modifier = Modifier.height(12.dp))

                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Column(modifier = Modifier.weight(1f)) {
                            Text("Local Developer Mode", fontWeight = FontWeight.SemiBold, fontSize = 14.sp, color = TextPrimary)
                            Text("Uses X-User-ID header for local sandbox testing", fontSize = 12.sp, color = TextSecondary)
                        }
                        Switch(
                            checked = state.isDevMode,
                            onCheckedChange = { viewModel.setDevMode(it) },
                            colors = SwitchDefaults.colors(checkedThumbColor = CyberCyan)
                        )
                    }

                    if (state.isDevMode) {
                        Spacer(modifier = Modifier.height(8.dp))
                        OutlinedTextField(
                            value = userIdInput,
                            onValueChange = {
                                userIdInput = it
                                viewModel.updateUserId(it)
                            },
                            label = { Text("Developer User ID") },
                            colors = OutlinedTextFieldDefaults.colors(
                                focusedTextColor = TextPrimary,
                                unfocusedTextColor = TextPrimary,
                                focusedBorderColor = CyberCyan,
                                unfocusedBorderColor = CyberSurfaceBorder
                            ),
                            modifier = Modifier.fillMaxWidth()
                        )
                    }
                }
            }

            // Architecture Info
            item {
                CyberCard {
                    Text(text = "CYBERSECURITY CLIENT ARCHITECTURE", fontSize = 11.sp, fontWeight = FontWeight.SemiBold, color = TextMuted)
                    Spacer(modifier = Modifier.height(6.dp))
                    Text(text = "Package: com.llmsecurityscanner", fontSize = 12.sp, color = TextPrimary)
                    Text(text = "Engine: FastAPI + ML Detection Sandbox", fontSize = 12.sp, color = TextSecondary)
                    Text(text = "Security: AES-GCM Keystore Encryption", fontSize = 12.sp, color = SeverityLow)
                }
            }
        }
    }
}
