package com.llmsecurityscanner.presentation.reports

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.llmsecurityscanner.presentation.components.CyberCard
import com.llmsecurityscanner.presentation.components.MetricCard
import com.llmsecurityscanner.presentation.components.SeverityBadge
import com.llmsecurityscanner.presentation.theme.*

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ReportsScreen(
    scanId: String,
    viewModel: ReportsViewModel,
    onBack: () -> Unit
) {
    val state by viewModel.uiState.collectAsState()
    val context = LocalContext.current

    LaunchedEffect(scanId) {
        viewModel.loadReport(scanId)
    }

    val report = state.report

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Audit Report", fontWeight = FontWeight.Bold, fontSize = 18.sp) },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.Default.ArrowBack, contentDescription = "Back", tint = TextPrimary)
                    }
                },
                actions = {
                    IconButton(
                        onClick = { viewModel.shareReportCsv(context, scanId) },
                        enabled = !state.isExporting && report != null
                    ) {
                        if (state.isExporting) {
                            CircularProgressIndicator(modifier = Modifier.size(20.dp), color = CyberCyan, strokeWidth = 2.dp)
                        } else {
                            Icon(Icons.Default.Share, contentDescription = "Share CSV", tint = CyberCyan)
                        }
                    }
                },
                colors = TopAppBarDefaults.topAppBarColors(containerColor = CyberSurface)
            )
        },
        containerColor = CyberBg
    ) { padding ->
        if (state.isLoading) {
            Box(modifier = Modifier.fillMaxSize().padding(padding), contentAlignment = Alignment.Center) {
                CircularProgressIndicator(color = CyberCyan)
            }
        } else if (report != null) {
            LazyColumn(
                modifier = Modifier
                    .fillMaxSize()
                    .padding(padding)
                    .padding(16.dp),
                verticalArrangement = Arrangement.spacedBy(16.dp)
            ) {
                // Executive Overview Card
                item {
                    CyberCard(borderColor = CyberCyan) {
                        Text(text = "EXECUTIVE SECURITY SUMMARY", fontSize = 11.sp, fontWeight = FontWeight.SemiBold, color = TextMuted)
                        Spacer(modifier = Modifier.height(6.dp))
                        Text(text = "Scan ID: $scanId", fontSize = 16.sp, fontWeight = FontWeight.Bold, color = TextPrimary)
                        Text(text = "Status: ${report.status} • Generated: ${report.generatedAt ?: "N/A"}", fontSize = 12.sp, color = TextSecondary)
                    }
                }

                // Summary Metric Cards
                item {
                    val summary = report.summary
                    Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                        MetricCard(
                            title = "Critical",
                            value = "${summary?.criticalSeverity ?: 0}",
                            accentColor = SeverityCritical,
                            modifier = Modifier.weight(1f)
                        )
                        MetricCard(
                            title = "High",
                            value = "${summary?.highSeverity ?: 0}",
                            accentColor = SeverityHigh,
                            modifier = Modifier.weight(1f)
                        )
                        MetricCard(
                            title = "Medium",
                            value = "${summary?.mediumSeverity ?: 0}",
                            accentColor = SeverityMedium,
                            modifier = Modifier.weight(1f)
                        )
                    }
                }

                // Findings Breakdown
                item {
                    Text(text = "VULNERABILITIES DETECTED (${report.findings.size})", fontSize = 12.sp, fontWeight = FontWeight.SemiBold, color = TextMuted)
                }

                if (report.findings.isEmpty()) {
                    item {
                        CyberCard {
                            Text("No vulnerabilities detected in this evaluation run.", color = SeverityLow, fontSize = 13.sp)
                        }
                    }
                } else {
                    items(report.findings) { f ->
                        CyberCard {
                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                horizontalArrangement = Arrangement.SpaceBetween,
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                Column(modifier = Modifier.weight(1f)) {
                                    Text(text = f.title, fontWeight = FontWeight.Bold, fontSize = 14.sp, color = TextPrimary)
                                    Text(text = "Category: ${f.category}", fontSize = 12.sp, color = TextSecondary)
                                }
                                SeverityBadge(severity = f.severity)
                            }
                        }
                    }
                }

                // Remediation Recommendations
                if (report.recommendations.isNotEmpty()) {
                    item {
                        CyberCard(borderColor = SeverityLow.copy(alpha = 0.5f)) {
                            Text(text = "RECOMMENDED SECURITY ACTIONS", fontSize = 11.sp, fontWeight = FontWeight.SemiBold, color = SeverityLow)
                            Spacer(modifier = Modifier.height(8.dp))
                            report.recommendations.forEach { r ->
                                Row(modifier = Modifier.fillMaxWidth().padding(vertical = 2.dp)) {
                                    Text(text = "• ", color = CyberCyan, fontWeight = FontWeight.Bold)
                                    Text(text = r, fontSize = 12.sp, color = TextPrimary)
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}
