package com.llmsecurityscanner.presentation.dashboard

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.ui.text.font.FontWeight
import com.llmsecurityscanner.presentation.components.*
import com.llmsecurityscanner.presentation.navigation.Screen
import com.llmsecurityscanner.presentation.theme.*

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun DashboardScreen(
    viewModel: DashboardViewModel,
    onNavigateToScan: () -> Unit,
    onNavigateToLiveScan: (String) -> Unit,
    onNavigateToSettings: () -> Unit
) {
    val state by viewModel.uiState.collectAsState()

    Scaffold(
        topBar = {
            TopAppBar(
                title = {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Icon(
                            imageVector = Icons.Default.Shield,
                            contentDescription = null,
                            tint = CyberCyan,
                            modifier = Modifier.size(24.dp)
                        )
                        Spacer(modifier = Modifier.width(8.dp))
                        Text("LLM Security Scanner", fontWeight = FontWeight.Bold, fontSize = 18.sp)
                    }
                },
                actions = {
                    IconButton(onClick = onNavigateToSettings) {
                        Icon(Icons.Default.Settings, contentDescription = "Settings", tint = TextSecondary)
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
                .padding(horizontal = 16.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp)
        ) {
            item {
                Spacer(modifier = Modifier.height(4.dp))
                // Quick Launch Card
                CyberCard(
                    borderColor = CyberCyan,
                    backgroundColor = CyberSurfaceCard
                ) {
                    Text(
                        text = "AI Security Posture",
                        fontSize = 18.sp,
                        fontWeight = FontWeight.Bold,
                        color = TextPrimary
                    )
                    Spacer(modifier = Modifier.height(4.dp))
                    Text(
                        text = "Scan LLMs, RAG pipelines, and AI agents for prompt injection, sensitive data leakage, and jailbreaks.",
                        fontSize = 13.sp,
                        color = TextSecondary
                    )
                    Spacer(modifier = Modifier.height(16.dp))
                    Button(
                        onClick = onNavigateToScan,
                        colors = ButtonDefaults.buttonColors(containerColor = CyberCyan, contentColor = CyberBg),
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Icon(Icons.Default.PlayArrow, contentDescription = null)
                        Spacer(modifier = Modifier.width(8.dp))
                        Text("Launch Security Scan", fontWeight = FontWeight.Bold)
                    }
                }
            }

            // Metrics Grid
            item {
                Text(
                    text = "VULNERABILITY METRICS",
                    fontSize = 12.sp,
                    fontWeight = FontWeight.SemiBold,
                    color = TextMuted,
                    letterSpacing = 1.sp
                )
                Spacer(modifier = Modifier.height(8.dp))
                Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                    MetricCard(
                        title = "Critical",
                        value = state.criticalCount.toString(),
                        accentColor = SeverityCritical,
                        modifier = Modifier.weight(1f)
                    )
                    MetricCard(
                        title = "High",
                        value = state.highCount.toString(),
                        accentColor = SeverityHigh,
                        modifier = Modifier.weight(1f)
                    )
                }
                Spacer(modifier = Modifier.height(12.dp))
                Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                    MetricCard(
                        title = "Medium",
                        value = state.mediumCount.toString(),
                        accentColor = SeverityMedium,
                        modifier = Modifier.weight(1f)
                    )
                    MetricCard(
                        title = "Low",
                        value = state.lowCount.toString(),
                        accentColor = SeverityLow,
                        modifier = Modifier.weight(1f)
                    )
                }
            }

            // Total Scans / Total Findings
            item {
                Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                    MetricCard(
                        title = "Total Scans",
                        value = state.totalScans.toString(),
                        icon = Icons.Default.Radar,
                        accentColor = CyberCyan,
                        modifier = Modifier.weight(1f)
                    )
                    MetricCard(
                        title = "Total Findings",
                        value = state.totalVulnerabilities.toString(),
                        icon = Icons.Default.BugReport,
                        accentColor = CyberPurple,
                        modifier = Modifier.weight(1f)
                    )
                }
            }

            // Recent Scans
            item {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Text(
                        text = "RECENT SCANS",
                        fontSize = 12.sp,
                        fontWeight = FontWeight.SemiBold,
                        color = TextMuted,
                        letterSpacing = 1.sp
                    )
                    IconButton(onClick = { viewModel.loadDashboardData() }) {
                        Icon(Icons.Default.Refresh, contentDescription = "Refresh", tint = CyberCyan, modifier = Modifier.size(20.dp))
                    }
                }
            }

            if (state.isLoading) {
                item {
                    Box(modifier = Modifier.fillMaxWidth().padding(24.dp), contentAlignment = Alignment.Center) {
                        CircularProgressIndicator(color = CyberCyan)
                    }
                }
            } else if (state.recentScans.isEmpty()) {
                item {
                    CyberCard {
                        Text(
                            text = "No scans performed yet. Tap 'Launch Security Scan' to start your first evaluation.",
                            fontSize = 13.sp,
                            color = TextSecondary
                        )
                    }
                }
            } else {
                items(state.recentScans) { scan ->
                    CyberCard(
                        modifier = Modifier
                            .fillMaxWidth()
                            .clickable { onNavigateToLiveScan(scan.id) }
                    ) {
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.SpaceBetween,
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Column(modifier = Modifier.weight(1f)) {
                                Text(
                                    text = "Scan ${scan.id.take(8)}...",
                                    fontWeight = FontWeight.Bold,
                                    fontSize = 14.sp,
                                    color = TextPrimary
                                )
                                Spacer(modifier = Modifier.height(2.dp))
                                Text(
                                    text = "Preset: ${scan.preset ?: "Custom"}",
                                    fontSize = 12.sp,
                                    color = TextSecondary
                                )
                            }
                            StatusBadge(status = scan.status)
                        }
                    }
                }
            }

            item {
                Spacer(modifier = Modifier.height(16.dp))
            }
        }
    }
}
