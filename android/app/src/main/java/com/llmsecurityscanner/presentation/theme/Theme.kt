package com.llmsecurityscanner.presentation.theme

import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.runtime.Composable

private val DarkColorScheme = darkColorScheme(
    primary = CyberCyan,
    onPrimary = CyberBg,
    primaryContainer = CyberCyanMuted,
    onPrimaryContainer = TextPrimary,
    secondary = CyberPurple,
    onSecondary = TextPrimary,
    background = CyberBg,
    onBackground = TextPrimary,
    surface = CyberSurface,
    onSurface = TextPrimary,
    surfaceVariant = CyberSurfaceCard,
    onSurfaceVariant = TextSecondary,
    outline = CyberSurfaceBorder,
    error = SeverityCritical,
    onError = TextPrimary
)

@Composable
fun LLMSecurityTheme(content: @Composable () -> Unit) {
    MaterialTheme(
        colorScheme = DarkColorScheme,
        typography = Typography,
        content = content
    )
}
