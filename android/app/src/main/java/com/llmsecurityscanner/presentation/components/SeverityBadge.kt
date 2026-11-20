package com.llmsecurityscanner.presentation.components

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.llmsecurityscanner.domain.model.Severity
import com.llmsecurityscanner.presentation.theme.*

@Composable
fun SeverityBadge(severity: String, modifier: Modifier = Modifier) {
    val sevEnum = Severity.fromString(severity)
    val (bgColor, textColor, borderColor) = when (sevEnum) {
        Severity.CRITICAL -> Triple(SeverityCritical.copy(alpha = 0.15f), SeverityCritical, SeverityCritical.copy(alpha = 0.5f))
        Severity.HIGH -> Triple(SeverityHigh.copy(alpha = 0.15f), SeverityHigh, SeverityHigh.copy(alpha = 0.5f))
        Severity.MEDIUM -> Triple(SeverityMedium.copy(alpha = 0.15f), SeverityMedium, SeverityMedium.copy(alpha = 0.5f))
        Severity.LOW -> Triple(SeverityLow.copy(alpha = 0.15f), SeverityLow, SeverityLow.copy(alpha = 0.5f))
        Severity.INFORMATIONAL -> Triple(SeverityInfo.copy(alpha = 0.15f), SeverityInfo, SeverityInfo.copy(alpha = 0.5f))
    }

    Box(
        modifier = modifier
            .background(bgColor, RoundedCornerShape(6.dp))
            .border(1.dp, borderColor, RoundedCornerShape(6.dp))
            .padding(horizontal = 8.dp, vertical = 3.dp),
        contentAlignment = Alignment.Center
    ) {
        Text(
            text = sevEnum.label,
            color = textColor,
            fontSize = 11.sp,
            fontWeight = FontWeight.Bold
        )
    }
}
