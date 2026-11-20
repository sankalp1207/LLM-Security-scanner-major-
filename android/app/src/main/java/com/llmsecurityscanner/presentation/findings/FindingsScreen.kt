package com.llmsecurityscanner.presentation.findings

import androidx.compose.foundation.clickable
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
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
import com.llmsecurityscanner.presentation.components.SeverityBadge
import com.llmsecurityscanner.presentation.theme.*

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun FindingsScreen(
    viewModel: FindingsViewModel,
    onFindingSelected: (String) -> Unit
) {
    val state by viewModel.uiState.collectAsState()

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Vulnerability Findings", fontWeight = FontWeight.Bold, fontSize = 18.sp) },
                colors = TopAppBarDefaults.topAppBarColors(containerColor = CyberSurface),
                actions = {
                    IconButton(onClick = { viewModel.loadFindings() }) {
                        Icon(Icons.Default.Refresh, contentDescription = "Refresh", tint = CyberCyan)
                    }
                }
            )
        },
        containerColor = CyberBg
    ) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .padding(16.dp)
        ) {
            // Search Input
            OutlinedTextField(
                value = state.searchQuery,
                onValueChange = { viewModel.setSearchQuery(it) },
                label = { Text("Search vulnerabilities...") },
                leadingIcon = { Icon(Icons.Default.Search, contentDescription = null, tint = TextMuted) },
                colors = OutlinedTextFieldDefaults.colors(
                    focusedTextColor = TextPrimary,
                    unfocusedTextColor = TextPrimary,
                    focusedBorderColor = CyberCyan,
                    unfocusedBorderColor = CyberSurfaceBorder
                ),
                modifier = Modifier.fillMaxWidth()
            )

            Spacer(modifier = Modifier.height(12.dp))

            // Severity Filter Chips
            Row(
                modifier = Modifier.fillMaxWidth().horizontalScroll(rememberScrollState()),
                horizontalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                val severities = listOf("CRITICAL", "HIGH", "MEDIUM", "LOW")
                severities.forEach { sev ->
                    val isSelected = state.selectedSeverityFilter == sev
                    FilterChip(
                        selected = isSelected,
                        onClick = { viewModel.setSeverityFilter(sev) },
                        label = { Text(sev) },
                        colors = FilterChipDefaults.filterChipColors(
                            selectedContainerColor = CyberCyan,
                            selectedLabelColor = CyberBg,
                            containerColor = CyberSurfaceCard,
                            labelColor = TextSecondary
                        )
                    )
                }
            }

            Spacer(modifier = Modifier.height(12.dp))

            if (state.isLoading) {
                Box(modifier = Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
                    CircularProgressIndicator(color = CyberCyan)
                }
            } else if (state.filteredFindings.isEmpty()) {
                Box(modifier = Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
                    Column(horizontalAlignment = Alignment.CenterHorizontally) {
                        Icon(Icons.Default.CheckCircle, contentDescription = null, tint = SeverityLow, modifier = Modifier.size(48.dp))
                        Spacer(modifier = Modifier.height(12.dp))
                        Text("No vulnerabilities matching criteria", color = TextSecondary, fontSize = 15.sp)
                    }
                }
            } else {
                LazyColumn(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                    items(state.filteredFindings) { finding ->
                        CyberCard(
                            modifier = Modifier
                                .fillMaxWidth()
                                .clickable { onFindingSelected(finding.id) }
                        ) {
                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                horizontalArrangement = Arrangement.SpaceBetween,
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                Column(modifier = Modifier.weight(1f)) {
                                    Text(
                                        text = finding.title,
                                        fontWeight = FontWeight.Bold,
                                        fontSize = 14.sp,
                                        color = TextPrimary
                                    )
                                    Spacer(modifier = Modifier.height(2.dp))
                                    Text(
                                        text = "Category: ${finding.category.replace("_", " ")}",
                                        fontSize = 12.sp,
                                        color = TextSecondary
                                    )
                                    if (finding.affectedComponent != null) {
                                        Text(
                                            text = "Component: ${finding.affectedComponent}",
                                            fontSize = 11.sp,
                                            color = TextMuted
                                        )
                                    }
                                }
                                SeverityBadge(severity = finding.severity)
                            }
                        }
                    }
                }
            }
        }
    }
}
