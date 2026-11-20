package com.llmsecurityscanner.presentation.scanner

import androidx.compose.foundation.clickable
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
import com.llmsecurityscanner.domain.model.PresetType
import com.llmsecurityscanner.presentation.components.CyberCard
import com.llmsecurityscanner.presentation.theme.*

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ScannerScreen(
    viewModel: ScannerViewModel,
    onNavigateToLiveScan: (String) -> Unit
) {
    val state by viewModel.uiState.collectAsState()

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Security Scanner Configuration", fontWeight = FontWeight.Bold, fontSize = 18.sp) },
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
            // Target Project Selection
            item {
                CyberCard {
                    Text(text = "TARGET PROJECT", fontSize = 11.sp, fontWeight = FontWeight.SemiBold, color = TextMuted)
                    Spacer(modifier = Modifier.height(8.dp))
                    if (state.projects.isEmpty()) {
                        Text("No projects available. Please create a project first.", color = SeverityHigh, fontSize = 13.sp)
                    } else {
                        state.projects.forEach { proj ->
                            val isSelected = proj.id == state.selectedProjectId
                            Row(
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .clickable { viewModel.setProjectId(proj.id) }
                                    .padding(vertical = 6.dp),
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                RadioButton(
                                    selected = isSelected,
                                    onClick = { viewModel.setProjectId(proj.id) },
                                    colors = RadioButtonDefaults.colors(selectedColor = CyberCyan)
                                )
                                Spacer(modifier = Modifier.width(8.dp))
                                Column {
                                    Text(text = proj.name, fontWeight = FontWeight.SemiBold, fontSize = 14.sp, color = TextPrimary)
                                    Text(text = "Target: ${proj.targetType}", fontSize = 12.sp, color = TextSecondary)
                                }
                            }
                        }
                    }
                }
            }

            // Scanning Preset Cards
            item {
                Text(
                    text = "SELECT SCAN PRESET",
                    fontSize = 11.sp,
                    fontWeight = FontWeight.SemiBold,
                    color = TextMuted,
                    letterSpacing = 1.sp
                )
                Spacer(modifier = Modifier.height(8.dp))

                val presets = listOf(
                    Triple(PresetType.QUICK_SCAN, "Fast evaluation (PII leakage, baseline prompt injection). 15 tests.", CyberCyan),
                    Triple(PresetType.FULL_SCAN, "Comprehensive evaluation (Jailbreak, RAG poison, indirect injection). 60 tests.", CyberPurple),
                    Triple(PresetType.DEEP_RED_TEAM, "Multi-turn adaptive fuzzing and autonomous attack graphs.", SeverityCritical)
                )

                presets.forEach { (preset, desc, accent) ->
                    val isSelected = state.selectedPreset == preset
                    CyberCard(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(vertical = 4.dp)
                            .clickable { viewModel.setPreset(preset) },
                        borderColor = if (isSelected) accent else CyberSurfaceBorder,
                        backgroundColor = if (isSelected) CyberSurfaceBorder.copy(alpha = 0.5f) else CyberSurfaceCard
                    ) {
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            RadioButton(
                                selected = isSelected,
                                onClick = { viewModel.setPreset(preset) },
                                colors = RadioButtonDefaults.colors(selectedColor = accent)
                            )
                            Spacer(modifier = Modifier.width(8.dp))
                            Column {
                                Text(text = preset.displayName, fontWeight = FontWeight.Bold, fontSize = 15.sp, color = TextPrimary)
                                Spacer(modifier = Modifier.height(2.dp))
                                Text(text = desc, fontSize = 12.sp, color = TextSecondary)
                            }
                        }
                    }
                }
            }

            // Deep Red Team Authorization Gate
            if (state.selectedPreset == PresetType.DEEP_RED_TEAM) {
                item {
                    CyberCard(borderColor = SeverityCritical) {
                        Text(text = "AUTHORIZATION ACKNOWLEDGEMENT", fontWeight = FontWeight.Bold, fontSize = 13.sp, color = SeverityCritical)
                        Spacer(modifier = Modifier.height(4.dp))
                        Text(
                            text = "Deep Red Team scans conduct intensive heuristic and adaptive payloads against the target endpoint. Confirm you are authorized to assess this system.",
                            fontSize = 12.sp,
                            color = TextSecondary
                        )
                        Spacer(modifier = Modifier.height(8.dp))
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Checkbox(
                                checked = state.externalTargetAuthorized,
                                onCheckedChange = { viewModel.setAuthorized(it) },
                                colors = CheckboxDefaults.colors(checkedColor = SeverityCritical)
                            )
                            Text(text = "I am authorized to test this target", fontSize = 13.sp, color = TextPrimary)
                        }
                    }
                }
            }

            // Error display
            if (state.errorMessage != null) {
                item {
                    CyberCard(borderColor = SeverityCritical) {
                        Text(text = state.errorMessage ?: "", color = SeverityCritical, fontSize = 13.sp)
                    }
                }
            }

            // Start Scan Button
            item {
                val canStart = state.selectedProjectId != null &&
                        (state.selectedPreset != PresetType.DEEP_RED_TEAM || state.externalTargetAuthorized) &&
                        !state.isScanning

                Button(
                    onClick = {
                        viewModel.startScan { scanId ->
                            onNavigateToLiveScan(scanId)
                        }
                    },
                    colors = ButtonDefaults.buttonColors(containerColor = CyberCyan, contentColor = CyberBg),
                    modifier = Modifier.fillMaxWidth().height(48.dp),
                    enabled = canStart
                ) {
                    if (state.isScanning) {
                        CircularProgressIndicator(modifier = Modifier.size(20.dp), color = CyberBg, strokeWidth = 2.dp)
                    } else {
                        Icon(Icons.Default.PlayArrow, contentDescription = null)
                        Spacer(modifier = Modifier.width(8.dp))
                        Text("Start Security Scan", fontWeight = FontWeight.Bold, fontSize = 15.sp)
                    }
                }
            }
        }
    }
}
