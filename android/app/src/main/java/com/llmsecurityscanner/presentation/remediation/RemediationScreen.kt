package com.llmsecurityscanner.presentation.remediation

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
import com.llmsecurityscanner.presentation.components.CyberCard
import com.llmsecurityscanner.presentation.components.UnifiedDiffViewer
import com.llmsecurityscanner.presentation.theme.*

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun RemediationScreen(
    findingId: String,
    viewModel: RemediationViewModel,
    onBack: () -> Unit
) {
    val state by viewModel.uiState.collectAsState()
    var showApplyConfirmDialog by remember { mutableStateOf(false) }

    LaunchedEffect(findingId) {
        viewModel.initForFinding(findingId)
    }

    val remediation = state.remediation
    val patch = state.selectedPatch

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Automated Remediation", fontWeight = FontWeight.Bold, fontSize = 18.sp) },
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
        if (state.isLoading) {
            Box(modifier = Modifier.fillMaxSize().padding(padding), contentAlignment = Alignment.Center) {
                CircularProgressIndicator(color = CyberPurple)
            }
        } else if (remediation != null) {
            LazyColumn(
                modifier = Modifier
                    .fillMaxSize()
                    .padding(padding)
                    .padding(16.dp),
                verticalArrangement = Arrangement.spacedBy(16.dp)
            ) {
                // Header Status Card
                item {
                    CyberCard(borderColor = CyberPurple) {
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.SpaceBetween,
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Text(text = "REMEDIATION WORKFLOW", fontSize = 11.sp, fontWeight = FontWeight.SemiBold, color = TextMuted)
                            Text(
                                text = remediation.status,
                                fontSize = 12.sp,
                                fontWeight = FontWeight.Bold,
                                color = if (remediation.status == "VERIFIED") SeverityLow else CyberPurple
                            )
                        }
                        Spacer(modifier = Modifier.height(6.dp))
                        Text(
                            text = remediation.suggestedFix ?: "No fix generated yet. Tap 'Generate Fix' to start AI patch creation.",
                            fontSize = 13.sp,
                            color = TextPrimary
                        )

                        if (remediation.patches.isEmpty()) {
                            Spacer(modifier = Modifier.height(12.dp))
                            Button(
                                onClick = { viewModel.generateFix(remediation.id) },
                                colors = ButtonDefaults.buttonColors(containerColor = CyberPurple),
                                modifier = Modifier.fillMaxWidth(),
                                enabled = !state.isOperating
                            ) {
                                if (state.isOperating) {
                                    CircularProgressIndicator(modifier = Modifier.size(16.dp), color = TextPrimary, strokeWidth = 2.dp)
                                } else {
                                    Icon(Icons.Default.AutoFixHigh, contentDescription = null)
                                    Spacer(modifier = Modifier.width(8.dp))
                                    Text("Generate Proposed Fix")
                                }
                            }
                        }
                    }
                }

                // Diff Viewer Card
                if (patch != null) {
                    item {
                        CyberCard {
                            Text(text = "PROPOSED CODE PATCH", fontSize = 11.sp, fontWeight = FontWeight.SemiBold, color = TextMuted)
                            Spacer(modifier = Modifier.height(4.dp))
                            Text(text = "File: ${patch.filePath}", fontSize = 13.sp, fontWeight = FontWeight.Bold, color = CyberCyan)
                            if (patch.explanation != null) {
                                Spacer(modifier = Modifier.height(4.dp))
                                Text(text = patch.explanation, fontSize = 12.sp, color = TextSecondary)
                            }
                            Spacer(modifier = Modifier.height(8.dp))
                            UnifiedDiffViewer(diffText = patch.diff)
                        }
                    }

                    // Approval & Rejection Decision Gate
                    item {
                        CyberCard {
                            Text(text = "HUMAN APPROVAL GATE", fontSize = 11.sp, fontWeight = FontWeight.SemiBold, color = TextMuted)
                            Spacer(modifier = Modifier.height(8.dp))
                            Text(
                                text = "Current Patch Status: ${patch.status ?: "PROPOSED"}",
                                fontSize = 13.sp,
                                fontWeight = FontWeight.Bold,
                                color = when (patch.status) {
                                    "APPROVED" -> SeverityLow
                                    "REJECTED" -> SeverityCritical
                                    "APPLIED" -> CyberCyan
                                    else -> SeverityMedium
                                }
                            )
                            Spacer(modifier = Modifier.height(12.dp))
                            Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                                Button(
                                    onClick = { viewModel.approvePatch(patch.id) },
                                    colors = ButtonDefaults.buttonColors(containerColor = SeverityLow),
                                    modifier = Modifier.weight(1f),
                                    enabled = !state.isOperating && patch.status != "APPROVED" && patch.status != "APPLIED"
                                ) {
                                    Icon(Icons.Default.Check, contentDescription = null)
                                    Spacer(modifier = Modifier.width(6.dp))
                                    Text("Approve")
                                }
                                Button(
                                    onClick = { viewModel.rejectPatch(patch.id) },
                                    colors = ButtonDefaults.buttonColors(containerColor = SeverityCritical),
                                    modifier = Modifier.weight(1f),
                                    enabled = !state.isOperating && patch.status != "REJECTED"
                                ) {
                                    Icon(Icons.Default.Close, contentDescription = null)
                                    Spacer(modifier = Modifier.width(6.dp))
                                    Text("Reject")
                                }
                            }

                            // Apply Patch Button
                            if (patch.status == "APPROVED") {
                                Spacer(modifier = Modifier.height(12.dp))
                                Button(
                                    onClick = { showApplyConfirmDialog = true },
                                    colors = ButtonDefaults.buttonColors(containerColor = CyberCyan, contentColor = CyberBg),
                                    modifier = Modifier.fillMaxWidth(),
                                    enabled = !state.isOperating
                                ) {
                                    Icon(Icons.Default.UploadFile, contentDescription = null)
                                    Spacer(modifier = Modifier.width(8.dp))
                                    Text("Apply Patch to Workspace", fontWeight = FontWeight.Bold)
                                }
                            }
                        }
                    }
                }

                // Verification & Rollback
                if (patch?.status == "APPLIED" || remediation.status == "APPLIED" || remediation.status == "VERIFIED") {
                    item {
                        CyberCard {
                            Text(text = "VERIFICATION & ROLLBACK", fontSize = 11.sp, fontWeight = FontWeight.SemiBold, color = TextMuted)
                            Spacer(modifier = Modifier.height(12.dp))
                            Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                                Button(
                                    onClick = { viewModel.verifyRemediation(remediation.id) },
                                    colors = ButtonDefaults.buttonColors(containerColor = SeverityLow),
                                    modifier = Modifier.weight(1f),
                                    enabled = !state.isOperating
                                ) {
                                    Icon(Icons.Default.PlayArrow, contentDescription = null)
                                    Spacer(modifier = Modifier.width(6.dp))
                                    Text("Run Verify")
                                }
                                Button(
                                    onClick = { viewModel.rollbackRemediation(remediation.id) },
                                    colors = ButtonDefaults.buttonColors(containerColor = SeverityCritical),
                                    modifier = Modifier.weight(1f),
                                    enabled = !state.isOperating
                                ) {
                                    Icon(Icons.Default.Undo, contentDescription = null)
                                    Spacer(modifier = Modifier.width(6.dp))
                                    Text("Rollback")
                                }
                            }

                            if (state.verificationResult != null) {
                                Spacer(modifier = Modifier.height(12.dp))
                                val v = state.verificationResult!!
                                Text(
                                    text = "Verification: ${if (v.vulnerabilityFixed) "VULNERABILITY RESOLVED" else "VULNERABILITY STILL PERSISTS"}",
                                    fontWeight = FontWeight.Bold,
                                    fontSize = 13.sp,
                                    color = if (v.vulnerabilityFixed) SeverityLow else SeverityCritical
                                )
                                Text(text = "Unit tests passed: ${v.unitTestsPassed}", fontSize = 12.sp, color = TextSecondary)
                            }
                        }
                    }
                }
            }
        }
    }

    if (showApplyConfirmDialog && patch != null) {
        AlertDialog(
            onDismissRequest = { showApplyConfirmDialog = false },
            title = { Text("Confirm Patch Application", color = TextPrimary, fontWeight = FontWeight.Bold) },
            text = {
                Text(
                    "Are you sure you want to apply this patch to '${patch.filePath}' in the authorized workspace? A backup will be preserved for instant rollback.",
                    color = TextSecondary
                )
            },
            confirmButton = {
                Button(
                    onClick = {
                        showApplyConfirmDialog = false
                        viewModel.applyPatch(patch.id)
                    },
                    colors = ButtonDefaults.buttonColors(containerColor = CyberCyan, contentColor = CyberBg)
                ) {
                    Text("Apply Patch", fontWeight = FontWeight.Bold)
                }
            },
            dismissButton = {
                TextButton(onClick = { showApplyConfirmDialog = false }) {
                    Text("Cancel", color = TextSecondary)
                }
            },
            containerColor = CyberSurfaceCard
        )
    }
}
