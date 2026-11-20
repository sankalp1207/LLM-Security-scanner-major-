package com.llmsecurityscanner.presentation.components

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.llmsecurityscanner.domain.model.ScanStatus
import com.llmsecurityscanner.presentation.theme.*

@Composable
fun StatusBadge(status: String, modifier: Modifier = Modifier) {
    val stEnum = ScanStatus.fromString(status)
    val (bgColor, textColor, borderColor) = when (stEnum) {
        ScanStatus.COMPLETED -> Triple(SeverityLow.copy(alpha = 0.15f), SeverityLow, SeverityLow.copy(alpha = 0.5f))
        ScanStatus.RUNNING -> Triple(CyberCyan.copy(alpha = 0.15f), CyberCyan, CyberCyan.copy(alpha = 0.5f))
        ScanStatus.FAILED -> Triple(SeverityCritical.copy(alpha = 0.15f), SeverityCritical, SeverityCritical.copy(alpha = 0.5f))
        ScanStatus.CANCELLED -> Triple(TextMuted.copy(alpha = 0.15f), TextMuted, TextMuted.copy(alpha = 0.5f))
        ScanStatus.PENDING -> Triple(SeverityMedium.copy(alpha = 0.15f), SeverityMedium, SeverityMedium.copy(alpha = 0.5f))
    }

    Box(
        modifier = modifier
            .background(bgColor, RoundedCornerShape(6.dp))
            .border(1.dp, borderColor, RoundedCornerShape(6.dp))
            .padding(horizontal = 8.dp, vertical = 3.dp),
        contentAlignment = Alignment.Center
    ) {
        Text(
            text = stEnum.label,
            color = textColor,
            fontSize = 11.sp,
            fontWeight = FontWeight.SemiBold
        )
    }
}
