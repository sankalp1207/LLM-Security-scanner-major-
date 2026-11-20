package com.llmsecurityscanner.presentation.scanner

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.llmsecurityscanner.presentation.components.*
import com.llmsecurityscanner.presentation.theme.*

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun LiveMonitorScreen(
    scanId: String,
    viewModel: ScannerViewModel,
    onBack: () -> Unit,
    onViewReport: (String) -> Unit
) {
    val state by viewModel.uiState.collectAsState()

    LaunchedEffect(scanId) {
        viewModel.attachToScan(scanId)
    }

    val scan = state.activeScan
    val progress = state.scanProgress
    val isFinished = scan?.status == "COMPLETED" || scan?.status == "FAILED" || scan?.status == "CANCELLED"

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Live Scan Monitor", fontWeight = FontWeight.Bold, fontSize = 18.sp) },
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
            // Header Card
            item {
                CyberCard(borderColor = CyberCyan) {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Column {
                            Text(text = "SCAN EXECUTION", fontSize = 11.sp, fontWeight = FontWeight.SemiBold, color = TextMuted)
                            Spacer(modifier = Modifier.height(2.dp))
                            Text(text = "Scan ID: ${scanId.take(12)}...", fontWeight = FontWeight.Bold, fontSize = 15.sp, color = TextPrimary)
                            Text(text = "Preset: ${scan?.preset ?: "Custom"}", fontSize = 12.sp, color = TextSecondary)
                        }
                        if (scan != null) {
                            StatusBadge(status = scan.status)
                        }
                    }

                    Spacer(modifier = Modifier.height(16.dp))

                    // Progress Bar
                    val pct = progress?.progressPercentage ?: scan?.progressPct ?: 0.0
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween
                    ) {
                        Text(text = "Progress", fontSize = 12.sp, color = TextSecondary)
                        Text(text = "${pct.toInt()}%", fontSize = 12.sp, fontWeight = FontWeight.Bold, color = CyberCyan)
                    }
                    Spacer(modifier = Modifier.height(6.dp))
                    LinearProgressIndicator(
                        progress = { (pct / 100.0).toFloat().coerceIn(0f, 1f) },
                        modifier = Modifier.fillMaxWidth().height(8.dp),
                        color = CyberCyan,
                        trackColor = CyberSurfaceBorder
                    )
                }
            }

            // Real-Time Stats
            item {
                Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                    MetricCard(
                        title = "Tests Completed",
                        value = "${progress?.completedTests ?: 0} / ${progress?.totalTests ?: 0}",
                        icon = Icons.Default.Speed,
                        accentColor = CyberCyan,
                        modifier = Modifier.weight(1f)
                    )
                    MetricCard(
                        title = "Findings",
                        value = "${progress?.findingsCount ?: scan?.summary?.vulnerabilitiesFound ?: 0}",
                        icon = Icons.Default.Warning,
                        accentColor = SeverityCritical,
                        modifier = Modifier.weight(1f)
                    )
                }
            }

            // Live SSE Log Terminal
            item {
                Text(
                    text = "REAL-TIME TELEMETRY STREAM",
                    fontSize = 11.sp,
                    fontWeight = FontWeight.SemiBold,
                    color = TextMuted,
                    letterSpacing = 1.sp
                )
                Spacer(modifier = Modifier.height(8.dp))
                LiveTerminalLog(events = state.liveEvents)
            }

            // Actions (Cancel or View Report)
            item {
                if (!isFinished) {
                    Button(
                        onClick = { viewModel.cancelScan(scanId) },
                        colors = ButtonDefaults.buttonColors(containerColor = SeverityCritical),
                        modifier = Modifier.fillMaxWidth().height(48.dp)
                    ) {
                        Icon(Icons.Default.Cancel, contentDescription = null)
                        Spacer(modifier = Modifier.width(8.dp))
                        Text("Cancel Security Scan", fontWeight = FontWeight.Bold)
                    }
                } else {
                    Button(
                        onClick = { onViewReport(scanId) },
                        colors = ButtonDefaults.buttonColors(containerColor = CyberCyan, contentColor = CyberBg),
                        modifier = Modifier.fillMaxWidth().height(48.dp)
                    ) {
                        Icon(Icons.Default.Assessment, contentDescription = null)
                        Spacer(modifier = Modifier.width(8.dp))
                        Text("View Security Audit Report", fontWeight = FontWeight.Bold)
                    }
                }
            }
        }
    }
}
