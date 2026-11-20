package com.llmsecurityscanner.presentation.components

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.llmsecurityscanner.data.model.ScanEventResponse
import com.llmsecurityscanner.presentation.theme.*

@Composable
fun LiveTerminalLog(events: List<ScanEventResponse>, modifier: Modifier = Modifier) {
    val listState = rememberLazyListState()

    LaunchedEffect(events.size) {
        if (events.isNotEmpty()) {
            listState.animateScrollToItem(events.size - 1)
        }
    }

    Box(
        modifier = modifier
            .fillMaxWidth()
            .background(Color(0xFF050811), RoundedCornerShape(8.dp))
            .border(1.dp, CyberCyan.copy(alpha = 0.3f), RoundedCornerShape(8.dp))
            .padding(12.dp)
    ) {
        LazyColumn(
            state = listState,
            modifier = Modifier.fillMaxWidth().height(200.dp)
        ) {
            items(events) { ev ->
                val logColor = when (ev.eventType.uppercase()) {
                    "VULNERABILITY_FOUND" -> SeverityCritical
                    "CATEGORY_COMPLETED" -> SeverityLow
                    "SCAN_COMPLETED" -> CyberCyan
                    "SCAN_FAILED" -> SeverityCritical
                    else -> TextSecondary
                }

                Row(modifier = Modifier.fillMaxWidth().padding(vertical = 2.dp)) {
                    Text(
                        text = "[#${ev.sequence}] ",
                        fontFamily = FontFamily.Monospace,
                        fontSize = 11.sp,
                        color = CyberCyan.copy(alpha = 0.6f)
                    )
                    Text(
                        text = ev.message,
                        fontFamily = FontFamily.Monospace,
                        fontSize = 11.sp,
                        color = logColor
                    )
                }
            }
        }
    }
}
