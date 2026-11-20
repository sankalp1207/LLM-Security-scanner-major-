package com.llmsecurityscanner.presentation.findings

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
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.llmsecurityscanner.presentation.components.CyberCard
import com.llmsecurityscanner.presentation.components.SeverityBadge
import com.llmsecurityscanner.presentation.theme.*

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun FindingDetailScreen(
    findingId: String,
    viewModel: FindingsViewModel,
    onBack: () -> Unit,
    onStartRemediation: (String) -> Unit
) {
    val state by viewModel.uiState.collectAsState()

    LaunchedEffect(findingId) {
        viewModel.selectFinding(findingId)
    }

    val finding = state.selectedFinding

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Finding Details", fontWeight = FontWeight.Bold, fontSize = 18.sp) },
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
        if (state.isLoading && finding == null) {
            Box(modifier = Modifier.fillMaxSize().padding(padding), contentAlignment = Alignment.Center) {
                CircularProgressIndicator(color = CyberCyan)
            }
        } else if (finding != null) {
            LazyColumn(
                modifier = Modifier
                    .fillMaxSize()
                    .padding(padding)
                    .padding(16.dp),
                verticalArrangement = Arrangement.spacedBy(16.dp)
            ) {
                // Header Card
                item {
                    CyberCard {
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.SpaceBetween,
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Text(text = finding.category.uppercase(), fontSize = 11.sp, fontWeight = FontWeight.SemiBold, color = TextMuted)
                            SeverityBadge(severity = finding.severity)
                        }
                        Spacer(modifier = Modifier.height(8.dp))
                        Text(text = finding.title, fontSize = 18.sp, fontWeight = FontWeight.Bold, color = TextPrimary)
                        Spacer(modifier = Modifier.height(6.dp))
                        Text(text = finding.description ?: "No description provided", fontSize = 13.sp, color = TextSecondary)
                        if (finding.affectedComponent != null) {
                            Spacer(modifier = Modifier.height(8.dp))
                            Text(text = "Affected Component: ${finding.affectedComponent}", fontSize = 12.sp, color = CyberCyan)
                        }
                    }
                }

                // Evidence Card
                if (finding.evidence != null && finding.evidence.isNotEmpty()) {
                    item {
                        CyberCard {
                            Text(text = "EXPLOIT EVIDENCE & PAYLOAD", fontSize = 11.sp, fontWeight = FontWeight.SemiBold, color = TextMuted)
                            Spacer(modifier = Modifier.height(8.dp))
                            Box(
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .background(Color(0xFF070B12), RoundedCornerShape(6.dp))
                                    .border(1.dp, CyberSurfaceBorder, RoundedCornerShape(6.dp))
                                    .padding(10.dp)
                            ) {
                                Text(
                                    text = finding.evidence.toString(),
                                    fontFamily = FontFamily.Monospace,
                                    fontSize = 12.sp,
                                    color = TextSecondary
                                )
                            }
                        }
                    }
                }

                // Recommendation Card
                if (!finding.recommendation.isNullOrBlank()) {
                    item {
                        CyberCard(borderColor = SeverityLow.copy(alpha = 0.5f)) {
                            Text(text = "RECOMMENDED REMEDIATION", fontSize = 11.sp, fontWeight = FontWeight.SemiBold, color = SeverityLow)
                            Spacer(modifier = Modifier.height(6.dp))
                            Text(text = finding.recommendation, fontSize = 13.sp, color = TextPrimary)
                        }
                    }
                }

                // Retest Status Card
                item {
                    CyberCard {
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.SpaceBetween,
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Column {
                                Text(text = "VERIFICATION STATUS", fontSize = 11.sp, fontWeight = FontWeight.SemiBold, color = TextMuted)
                                Text(
                                    text = finding.retestStatus ?: "UNTESTED",
                                    fontSize = 14.sp,
                                    fontWeight = FontWeight.Bold,
                                    color = if (finding.retestStatus == "PASSED" || finding.retestStatus == "FIXED") SeverityLow else SeverityMedium
                                )
                            }
                            Button(
                                onClick = { viewModel.retestFinding(finding.id) },
                                colors = ButtonDefaults.buttonColors(containerColor = CyberSurfaceBorder),
                                enabled = !state.isRetesting
                            ) {
                                if (state.isRetesting) {
                                    CircularProgressIndicator(modifier = Modifier.size(16.dp), color = CyberCyan, strokeWidth = 2.dp)
                                } else {
                                    Icon(Icons.Default.Refresh, contentDescription = null, tint = CyberCyan, modifier = Modifier.size(16.dp))
                                    Spacer(modifier = Modifier.width(6.dp))
                                    Text("Retest Finding", fontSize = 12.sp, color = TextPrimary)
                                }
                            }
                        }

                        if (state.retestResult != null) {
                            Spacer(modifier = Modifier.height(8.dp))
                            val res = state.retestResult!!
                            Text(
                                text = "Retest completed: ${if (res.passed) "Vulnerability Resolved" else "Vulnerability Still Present"}",
                                fontSize = 12.sp,
                                fontWeight = FontWeight.Bold,
                                color = if (res.passed) SeverityLow else SeverityCritical
                            )
                        }
                    }
                }

                // Remediation Action
                item {
                    Button(
                        onClick = { onStartRemediation(finding.id) },
                        colors = ButtonDefaults.buttonColors(containerColor = CyberPurple, contentColor = TextPrimary),
                        modifier = Modifier.fillMaxWidth().height(48.dp)
                    ) {
                        Icon(Icons.Default.AutoFixHigh, contentDescription = null)
                        Spacer(modifier = Modifier.width(8.dp))
                        Text("Launch Automated Remediation", fontWeight = FontWeight.Bold, fontSize = 15.sp)
                    }
                }
            }
        }
    }
}
