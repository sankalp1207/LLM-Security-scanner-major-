package com.llmsecurityscanner.presentation.copilot

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.rememberScrollState
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
fun CopilotScreen(viewModel: CopilotViewModel) {
    val state by viewModel.uiState.collectAsState()
    var inputText by remember { mutableStateOf("") }
    val listState = rememberLazyListState()

    LaunchedEffect(state.messages.size) {
        if (state.messages.isNotEmpty()) {
            listState.animateScrollToItem(state.messages.size - 1)
        }
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Icon(Icons.Default.SmartToy, contentDescription = null, tint = CyberPurple)
                        Spacer(modifier = Modifier.width(8.dp))
                        Text("AI Security Copilot", fontWeight = FontWeight.Bold, fontSize = 18.sp)
                    }
                },
                colors = TopAppBarDefaults.topAppBarColors(containerColor = CyberSurface)
            )
        },
        containerColor = CyberBg
    ) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
        ) {
            // Quick Prompt Chips
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 16.dp, vertical = 8.dp)
                    .horizontalScroll(rememberScrollState()),
                horizontalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                val prompts = listOf(
                    "Explain critical vulnerabilities",
                    "How to fix prompt injection?",
                    "Analyze RAG data leakage",
                    "Compare latest scans"
                )
                prompts.forEach { p ->
                    SuggestionChip(
                        onClick = { viewModel.sendMessage(p) },
                        label = { Text(p, fontSize = 12.sp) },
                        colors = SuggestionChipDefaults.suggestionChipColors(
                            containerColor = CyberSurfaceCard,
                            labelColor = CyberCyan
                        )
                    )
                }
            }

            // Message History
            Box(modifier = Modifier.weight(1f).padding(horizontal = 16.dp)) {
                if (state.messages.isEmpty() && !state.isLoading) {
                    Box(modifier = Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
                        Column(horizontalAlignment = Alignment.CenterHorizontally) {
                            Icon(Icons.Default.Security, contentDescription = null, tint = CyberPurple.copy(alpha = 0.5f), modifier = Modifier.size(48.dp))
                            Spacer(modifier = Modifier.height(12.dp))
                            Text("AI Security Copilot Ready", color = TextPrimary, fontWeight = FontWeight.Bold)
                            Spacer(modifier = Modifier.height(4.dp))
                            Text("Ask questions about findings, scans, or mitigations", color = TextSecondary, fontSize = 12.sp)
                        }
                    }
                } else {
                    LazyColumn(
                        state = listState,
                        verticalArrangement = Arrangement.spacedBy(12.dp),
                        modifier = Modifier.fillMaxSize()
                    ) {
                        items(state.messages) { msg ->
                            val isUser = msg.role == "user"
                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                horizontalArrangement = if (isUser) Arrangement.End else Arrangement.Start
                            ) {
                                Box(
                                    modifier = Modifier
                                        .widthIn(max = 300.dp)
                                        .background(
                                            if (isUser) CyberCyan.copy(alpha = 0.2f) else CyberSurfaceCard,
                                            RoundedCornerShape(12.dp)
                                        )
                                        .border(
                                            1.dp,
                                            if (isUser) CyberCyan else CyberSurfaceBorder,
                                            RoundedCornerShape(12.dp)
                                        )
                                        .padding(12.dp)
                                ) {
                                    Column {
                                        Text(
                                            text = if (isUser) "You" else "Copilot",
                                            fontWeight = FontWeight.Bold,
                                            fontSize = 11.sp,
                                            color = if (isUser) CyberCyan else CyberPurple
                                        )
                                        Spacer(modifier = Modifier.height(4.dp))
                                        Text(
                                            text = msg.content,
                                            fontSize = 13.sp,
                                            color = TextPrimary
                                        )
                                    }
                                }
                            }
                        }

                        if (state.isSending) {
                            item {
                                Row(horizontalArrangement = Arrangement.Start) {
                                    Box(
                                        modifier = Modifier
                                            .background(CyberSurfaceCard, RoundedCornerShape(12.dp))
                                            .padding(12.dp)
                                    ) {
                                        Row(verticalAlignment = Alignment.CenterVertically) {
                                            CircularProgressIndicator(modifier = Modifier.size(16.dp), color = CyberPurple, strokeWidth = 2.dp)
                                            Spacer(modifier = Modifier.width(8.dp))
                                            Text("Analyzing security telemetry...", fontSize = 12.sp, color = TextSecondary)
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }

            // Input Bar
            Surface(
                color = CyberSurface,
                modifier = Modifier.fillMaxWidth()
            ) {
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(horizontal = 16.dp, vertical = 8.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    OutlinedTextField(
                        value = inputText,
                        onValueChange = { inputText = it },
                        placeholder = { Text("Ask Copilot...", color = TextMuted) },
                        colors = OutlinedTextFieldDefaults.colors(
                            focusedTextColor = TextPrimary,
                            unfocusedTextColor = TextPrimary,
                            focusedBorderColor = CyberCyan,
                            unfocusedBorderColor = CyberSurfaceBorder
                        ),
                        modifier = Modifier.weight(1f)
                    )
                    Spacer(modifier = Modifier.width(8.dp))
                    IconButton(
                        onClick = {
                            if (inputText.isNotBlank()) {
                                val text = inputText
                                inputText = ""
                                viewModel.sendMessage(text)
                            }
                        },
                        enabled = inputText.isNotBlank() && !state.isSending
                    ) {
                        Icon(
                            Icons.Default.Send,
                            contentDescription = "Send",
                            tint = if (inputText.isNotBlank() && !state.isSending) CyberCyan else TextMuted
                        )
                    }
                }
            }
        }
    }
}
