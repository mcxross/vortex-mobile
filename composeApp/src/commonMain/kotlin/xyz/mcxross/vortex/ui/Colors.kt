package xyz.mcxross.vortex.ui

import androidx.compose.material3.darkColorScheme
import androidx.compose.ui.graphics.Color

val VortexBg = Color(0xFF121212)
val VortexSurface = Color(0xFF1E1E1E)
val VortexPrimary = Color(0xFF40E0D0)
val VortexOnPrimary = Color(0xFF003833)
val VortexSecondary = Color(0xFFB0BEC5)
val VortexSuccess = Color(0xFF00C853)
val VortexError = Color(0xFFD50000)
val VortexTerminalBg = Color(0xFF0A0A0A)
val VortexTerminalText = Color(0xFF00E676)

val VortexColorScheme =
  darkColorScheme(
    primary = VortexPrimary,
    onPrimary = VortexOnPrimary,
    secondary = VortexSecondary,
    background = VortexBg,
    surface = VortexSurface,
    onBackground = Color(0xFFE0E0E0),
    onSurface = Color(0xFFE0E0E0),
    surfaceVariant = VortexSurface,
    onSurfaceVariant = VortexSecondary,
  )
