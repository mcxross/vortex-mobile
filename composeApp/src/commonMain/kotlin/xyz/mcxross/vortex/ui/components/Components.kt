package xyz.mcxross.vortex.ui.components

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.OutlinedTextFieldDefaults
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import xyz.mcxross.vortex.ui.VortexError
import xyz.mcxross.vortex.ui.VortexPrimary
import xyz.mcxross.vortex.ui.VortexSecondary
import xyz.mcxross.vortex.ui.VortexSuccess
import xyz.mcxross.vortex.ui.VortexSurface

@Composable
fun VortexTextField(
  value: String,
  label: String,
  onValueChange: (String) -> Unit,
  modifier: Modifier = Modifier,
  enabled: Boolean = true,
  singleLine: Boolean = true,
  keyboardType: KeyboardType = KeyboardType.Text,
  monospace: Boolean = false,
) {
  OutlinedTextField(
    value = value,
    onValueChange = onValueChange,
    label = { Text(label) },
    modifier = modifier.fillMaxWidth(),
    enabled = enabled,
    singleLine = singleLine,
    keyboardOptions = KeyboardOptions(keyboardType = keyboardType),
    shape = RoundedCornerShape(12.dp),
    textStyle =
      if (monospace) {
        TextStyle(fontFamily = FontFamily.Monospace)
      } else {
        TextStyle.Default
      },
    colors =
      OutlinedTextFieldDefaults.colors(
        focusedBorderColor = MaterialTheme.colorScheme.primary,
        unfocusedBorderColor = MaterialTheme.colorScheme.surfaceVariant,
        focusedContainerColor = MaterialTheme.colorScheme.surface,
        unfocusedContainerColor = MaterialTheme.colorScheme.surface,
      ),
  )
}

@Composable
fun PrimaryActionButton(
  text: String,
  onClick: () -> Unit,
  modifier: Modifier = Modifier,
  enabled: Boolean = true,
  height: Dp = 48.dp,
) {
  Button(
    onClick = onClick,
    modifier = modifier.fillMaxWidth().height(height),
    enabled = enabled,
    shape = RoundedCornerShape(12.dp),
    colors =
      ButtonDefaults.buttonColors(
        containerColor = MaterialTheme.colorScheme.primary,
        contentColor = MaterialTheme.colorScheme.onPrimary,
        disabledContainerColor = MaterialTheme.colorScheme.surfaceVariant,
      ),
  ) {
    Text(text, fontWeight = FontWeight.Bold)
  }
}

@Composable
fun SecondaryActionButton(
  text: String,
  onClick: () -> Unit,
  modifier: Modifier = Modifier,
  enabled: Boolean = true,
  height: Dp = 48.dp,
) {
  Button(
    onClick = onClick,
    modifier = modifier.fillMaxWidth().height(height),
    enabled = enabled,
    shape = RoundedCornerShape(10.dp),
    colors =
      ButtonDefaults.buttonColors(
        containerColor = MaterialTheme.colorScheme.surfaceVariant,
        contentColor = MaterialTheme.colorScheme.onSurface,
      ),
  ) {
    Text(text, fontWeight = FontWeight.Bold)
  }
}

@Composable
fun SectionCard(title: String, modifier: Modifier = Modifier, content: @Composable () -> Unit) {
  Card(
    modifier = modifier.fillMaxWidth(),
    colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
    shape = RoundedCornerShape(12.dp),
  ) {
    Column(modifier = Modifier.padding(16.dp)) {
      Text(
        text = title,
        style = MaterialTheme.typography.titleMedium,
        color = MaterialTheme.colorScheme.primary,
        fontWeight = FontWeight.Bold,
      )
      Spacer(modifier = Modifier.height(12.dp))
      content()
    }
  }
}

enum class StatusKind {
  Idle,
  Running,
  Success,
  Error,
}

data class OperationStatus(val title: String, val detail: String, val kind: StatusKind)

@Composable
fun InlineStatus(status: OperationStatus, isProcessing: Boolean) {
  val accent =
    when (status.kind) {
      StatusKind.Success -> VortexSuccess
      StatusKind.Error -> VortexError
      StatusKind.Running -> VortexPrimary
      StatusKind.Idle -> VortexSecondary
    }
  Card(
    modifier = Modifier.fillMaxWidth(),
    colors = CardDefaults.cardColors(containerColor = VortexSurface),
    shape = RoundedCornerShape(10.dp),
    border = BorderStroke(1.dp, accent.copy(alpha = 0.6f)),
  ) {
    Column(modifier = Modifier.padding(12.dp)) {
      Text(
        text = status.title,
        style = MaterialTheme.typography.labelLarge,
        color = accent,
        fontWeight = FontWeight.Bold,
      )
      Spacer(modifier = Modifier.height(4.dp))
      Text(
        text = status.detail,
        style = MaterialTheme.typography.bodySmall,
        color = MaterialTheme.colorScheme.onSurface,
      )
      if (isProcessing && status.kind == StatusKind.Running) {
        Spacer(modifier = Modifier.height(10.dp))
        LinearProgressIndicator(
          modifier = Modifier.fillMaxWidth(),
          color = accent,
          trackColor = MaterialTheme.colorScheme.surfaceVariant,
        )
      }
    }
  }
}
