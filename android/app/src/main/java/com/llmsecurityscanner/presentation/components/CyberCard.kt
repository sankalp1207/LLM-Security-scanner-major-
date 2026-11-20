package com.llmsecurityscanner.presentation.components

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import com.llmsecurityscanner.presentation.theme.CyberSurfaceBorder
import com.llmsecurityscanner.presentation.theme.CyberSurfaceCard

@Composable
fun CyberCard(
    modifier: Modifier = Modifier,
    borderColor: Color = CyberSurfaceBorder,
    backgroundColor: Color = CyberSurfaceCard,
    cornerRadius: Dp = 12.dp,
    contentPadding: Dp = 16.dp,
    content: @Composable ColumnScope.() -> Unit
) {
    Card(
        modifier = modifier,
        shape = RoundedCornerShape(cornerRadius),
        colors = CardDefaults.cardColors(containerColor = backgroundColor),
        border = BorderStroke(1.dp, borderColor)
    ) {
        Column(modifier = Modifier.padding(contentPadding)) {
            content()
        }
    }
}
