package com.llmsecurityscanner.presentation.components

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.llmsecurityscanner.presentation.theme.*

@Composable
fun UnifiedDiffViewer(diffText: String, modifier: Modifier = Modifier) {
    val lines = diffText.lines()

    Box(
        modifier = modifier
            .fillMaxWidth()
            .background(Color(0xFF0D1117), RoundedCornerShape(8.dp))
            .border(1.dp, CyberSurfaceBorder, RoundedCornerShape(8.dp))
            .padding(10.dp)
    ) {
        LazyColumn(modifier = Modifier.fillMaxWidth()) {
            items(lines) { line ->
                val (bgColor, textColor) = when {
                    line.startsWith("+") && !line.startsWith("+++") -> Pair(DiffAddedBg.copy(alpha = 0.35f), DiffAddedText)
                    line.startsWith("-") && !line.startsWith("---") -> Pair(DiffRemovedBg.copy(alpha = 0.35f), DiffRemovedText)
                    line.startsWith("@@") -> Pair(CyberPurple.copy(alpha = 0.2f), CyberPurple)
                    else -> Pair(Color.Transparent, TextSecondary)
                }

                Box(
                    modifier = Modifier
                        .fillMaxWidth()
                        .background(bgColor)
                        .padding(horizontal = 6.dp, vertical = 2.dp)
                ) {
                    Text(
                        text = line.ifEmpty { " " },
                        fontFamily = FontFamily.Monospace,
                        fontSize = 12.sp,
                        color = textColor,
                        fontWeight = if (line.startsWith("+") || line.startsWith("-")) FontWeight.Medium else FontWeight.Normal
                    )
                }
            }
        }
    }
}
