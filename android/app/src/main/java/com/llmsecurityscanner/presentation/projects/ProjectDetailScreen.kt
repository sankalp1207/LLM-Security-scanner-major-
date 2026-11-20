package com.llmsecurityscanner.presentation.projects

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
fun ProjectDetailScreen(
    projectId: String,
    viewModel: ProjectsViewModel,
    onBack: () -> Unit,
    onStartScan: (String) -> Unit
) {
    val state by viewModel.uiState.collectAsState()

    LaunchedEffect(projectId) {
        viewModel.selectProject(projectId)
    }

    val project = state.selectedProject

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(project?.name ?: "Project Details", fontWeight = FontWeight.Bold, fontSize = 18.sp) },
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
        if (state.isLoading && project == null) {
            Box(modifier = Modifier.fillMaxSize().padding(padding), contentAlignment = Alignment.Center) {
                CircularProgressIndicator(color = CyberCyan)
            }
        } else if (project != null) {
            LazyColumn(
                modifier = Modifier
                    .fillMaxSize()
                    .padding(padding)
                    .padding(16.dp),
                verticalArrangement = Arrangement.spacedBy(16.dp)
            ) {
                // Info Card
                item {
                    CyberCard {
                        Text(text = "TARGET CONFIGURATION", fontSize = 11.sp, fontWeight = FontWeight.SemiBold, color = TextMuted)
                        Spacer(modifier = Modifier.height(8.dp))
                        Text(text = project.name, fontSize = 18.sp, fontWeight = FontWeight.Bold, color = TextPrimary)
                        Spacer(modifier = Modifier.height(4.dp))
                        Text(text = project.description ?: "No description", fontSize = 13.sp, color = TextSecondary)
                        Spacer(modifier = Modifier.height(12.dp))
                        Text(text = "Target URL: ${project.targetUrl ?: "Local sandbox"}", fontSize = 12.sp, color = CyberCyan)
                        Text(text = "Type: ${project.targetType} | Env: ${project.environment}", fontSize = 12.sp, color = TextMuted)
                    }
                }

                // Diagnostics Card
                item {
                    CyberCard(borderColor = CyberCyan) {
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.SpaceBetween,
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Text(text = "CONNECTION DIAGNOSTICS", fontSize = 11.sp, fontWeight = FontWeight.SemiBold, color = TextMuted)
                            Button(
                                onClick = { viewModel.verifyConnection(project.id) },
                                colors = ButtonDefaults.buttonColors(containerColor = CyberSurfaceBorder),
                                enabled = !state.isVerifying
                            ) {
                                if (state.isVerifying) {
                                    CircularProgressIndicator(modifier = Modifier.size(16.dp), color = CyberCyan, strokeWidth = 2.dp)
                                } else {
                                    Icon(Icons.Default.Speed, contentDescription = null, tint = CyberCyan, modifier = Modifier.size(16.dp))
                                    Spacer(modifier = Modifier.width(6.dp))
                                    Text("Ping Target", fontSize = 12.sp, color = TextPrimary)
                                }
                            }
                        }

                        if (state.verificationResult != null) {
                            Spacer(modifier = Modifier.height(12.dp))
                            val res = state.verificationResult!!
                            val isReachable = res.reachable
                            Box(
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .background(
                                        if (isReachable) SeverityLow.copy(alpha = 0.15f) else SeverityCritical.copy(alpha = 0.15f),
                                        RoundedCornerShape(6.dp)
                                    )
                                    .border(
                                        1.dp,
                                        if (isReachable) SeverityLow else SeverityCritical,
                                        RoundedCornerShape(6.dp)
                                    )
                                    .padding(10.dp)
                            ) {
                                Column {
                                    Text(
                                        text = if (isReachable) "Target Reachable" else "Target Unreachable",
                                        fontWeight = FontWeight.Bold,
                                        fontSize = 13.sp,
                                        color = if (isReachable) SeverityLow else SeverityCritical
                                    )
                                    if (res.latencyMs != null) {
                                        Text(text = "Latency: ${res.latencyMs} ms", fontSize = 12.sp, color = TextPrimary)
                                    }
                                    if (res.message != null) {
                                        Text(text = res.message ?: "", fontSize = 11.sp, color = TextSecondary)
                                    }
                                }
                            }
                        }
                    }
                }

                // Supported Categories
                item {
                    CyberCard {
                        Text(text = "SCAN CAPABILITIES", fontSize = 11.sp, fontWeight = FontWeight.SemiBold, color = TextMuted)
                        Spacer(modifier = Modifier.height(8.dp))
                        val categories = state.capabilities?.supportedCategories
                            ?: listOf("prompt_injection", "jailbreak", "sensitive_data", "rag_security")

                        categories.forEach { cat ->
                            Row(
                                modifier = Modifier.fillMaxWidth().padding(vertical = 4.dp),
                                horizontalArrangement = Arrangement.SpaceBetween
                            ) {
                                Text(text = cat.replace("_", " ").uppercase(), fontSize = 12.sp, color = TextPrimary)
                                Text(text = "ENABLED", fontSize = 11.sp, fontWeight = FontWeight.Bold, color = SeverityLow)
                            }
                        }
                    }
                }

                // Launch Scan Button
                item {
                    Button(
                        onClick = { onStartScan(project.id) },
                        colors = ButtonDefaults.buttonColors(containerColor = CyberCyan, contentColor = CyberBg),
                        modifier = Modifier.fillMaxWidth().height(48.dp)
                    ) {
                        Icon(Icons.Default.Security, contentDescription = null)
                        Spacer(modifier = Modifier.width(8.dp))
                        Text("Configure Security Scan", fontWeight = FontWeight.Bold, fontSize = 15.sp)
                    }
                }
            }
        }
    }
}
