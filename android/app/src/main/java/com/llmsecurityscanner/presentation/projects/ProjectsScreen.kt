package com.llmsecurityscanner.presentation.projects

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
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
fun ProjectsScreen(
    viewModel: ProjectsViewModel,
    onProjectSelected: (String) -> Unit
) {
    val state by viewModel.uiState.collectAsState()
    var showCreateDialog by remember { mutableStateOf(false) }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("AI Security Projects", fontWeight = FontWeight.Bold, fontSize = 18.sp) },
                colors = TopAppBarDefaults.topAppBarColors(containerColor = CyberSurface),
                actions = {
                    IconButton(onClick = { viewModel.loadProjects() }) {
                        Icon(Icons.Default.Refresh, contentDescription = "Refresh", tint = CyberCyan)
                    }
                }
            )
        },
        floatingActionButton = {
            FloatingActionButton(
                onClick = { showCreateDialog = true },
                containerColor = CyberCyan,
                contentColor = CyberBg
            ) {
                Icon(Icons.Default.Add, contentDescription = "New Project")
            }
        },
        containerColor = CyberBg
    ) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .padding(16.dp)
        ) {
            if (state.errorMessage != null) {
                CyberCard(borderColor = SeverityCritical) {
                    Text(
                        text = state.errorMessage ?: "",
                        color = SeverityCritical,
                        fontSize = 13.sp
                    )
                }
                Spacer(modifier = Modifier.height(12.dp))
            }

            if (state.isLoading) {
                Box(modifier = Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
                    CircularProgressIndicator(color = CyberCyan)
                }
            } else if (state.projects.isEmpty()) {
                Box(modifier = Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
                    Column(horizontalAlignment = Alignment.CenterHorizontally) {
                        Icon(Icons.Default.FolderOpen, contentDescription = null, tint = TextMuted, modifier = Modifier.size(48.dp))
                        Spacer(modifier = Modifier.height(12.dp))
                        Text("No projects configured yet", color = TextSecondary, fontSize = 15.sp)
                        Spacer(modifier = Modifier.height(8.dp))
                        Text("Tap + to register your first LLM target", color = TextMuted, fontSize = 12.sp)
                    }
                }
            } else {
                LazyColumn(verticalArrangement = Arrangement.spacedBy(12.dp)) {
                    items(state.projects) { project ->
                        CyberCard(
                            modifier = Modifier
                                .fillMaxWidth()
                                .clickable { onProjectSelected(project.id) }
                        ) {
                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                horizontalArrangement = Arrangement.SpaceBetween,
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                Column(modifier = Modifier.weight(1f)) {
                                    Text(
                                        text = project.name,
                                        fontWeight = FontWeight.Bold,
                                        fontSize = 15.sp,
                                        color = TextPrimary
                                    )
                                    Spacer(modifier = Modifier.height(4.dp))
                                    Text(
                                        text = project.description ?: "No description provided",
                                        fontSize = 12.sp,
                                        color = TextSecondary,
                                        maxLines = 2
                                    )
                                    Spacer(modifier = Modifier.height(6.dp))
                                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                                        Text(
                                            text = "Target: ${project.targetType}",
                                            fontSize = 11.sp,
                                            color = CyberCyan
                                        )
                                        Text(
                                            text = "• Env: ${project.environment}",
                                            fontSize = 11.sp,
                                            color = TextMuted
                                        )
                                    }
                                }
                                Icon(
                                    Icons.Default.ChevronRight,
                                    contentDescription = null,
                                    tint = TextMuted
                                )
                            }
                        }
                    }
                }
            }
        }
    }

    if (showCreateDialog) {
        CreateProjectDialog(
            onDismiss = { showCreateDialog = false },
            onConfirm = { name, desc, targetType, targetUrl ->
                viewModel.createProject(name, desc, targetType, targetUrl) {
                    showCreateDialog = false
                }
            }
        )
    }
}

@Composable
fun CreateProjectDialog(
    onDismiss: () -> Unit,
    onConfirm: (name: String, desc: String?, targetType: String, targetUrl: String?) -> Unit
) {
    var name by remember { mutableStateOf("") }
    var desc by remember { mutableStateOf("") }
    var targetUrl by remember { mutableStateOf("http://10.0.2.2:8000/api/v1/demo-rag/query") }
    var targetType by remember { mutableStateOf("custom_http") }

    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("New AI Security Project", color = TextPrimary, fontWeight = FontWeight.Bold) },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                OutlinedTextField(
                    value = name,
                    onValueChange = { name = it },
                    label = { Text("Project Name") },
                    colors = OutlinedTextFieldDefaults.colors(
                        focusedTextColor = TextPrimary,
                        unfocusedTextColor = TextPrimary,
                        focusedBorderColor = CyberCyan,
                        unfocusedBorderColor = CyberSurfaceBorder
                    ),
                    modifier = Modifier.fillMaxWidth()
                )
                OutlinedTextField(
                    value = desc,
                    onValueChange = { desc = it },
                    label = { Text("Description") },
                    colors = OutlinedTextFieldDefaults.colors(
                        focusedTextColor = TextPrimary,
                        unfocusedTextColor = TextPrimary,
                        focusedBorderColor = CyberCyan,
                        unfocusedBorderColor = CyberSurfaceBorder
                    ),
                    modifier = Modifier.fillMaxWidth()
                )
                OutlinedTextField(
                    value = targetUrl,
                    onValueChange = { targetUrl = it },
                    label = { Text("Target Endpoint URL") },
                    colors = OutlinedTextFieldDefaults.colors(
                        focusedTextColor = TextPrimary,
                        unfocusedTextColor = TextPrimary,
                        focusedBorderColor = CyberCyan,
                        unfocusedBorderColor = CyberSurfaceBorder
                    ),
                    modifier = Modifier.fillMaxWidth()
                )
            }
        },
        confirmButton = {
            Button(
                onClick = { if (name.isNotBlank()) onConfirm(name, desc.ifBlank { null }, targetType, targetUrl) },
                colors = ButtonDefaults.buttonColors(containerColor = CyberCyan, contentColor = CyberBg),
                enabled = name.isNotBlank()
            ) {
                Text("Create Project", fontWeight = FontWeight.Bold)
            }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) {
                Text("Cancel", color = TextSecondary)
            }
        },
        containerColor = CyberSurfaceCard
    )
}
