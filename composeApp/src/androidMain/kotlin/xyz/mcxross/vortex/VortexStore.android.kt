package xyz.mcxross.vortex.vortex

import android.content.Context
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.ui.platform.LocalContext
import androidx.core.content.edit

@Composable
actual fun rememberVortexStore(): VortexStore {
  val context = LocalContext.current
  return remember(context) { VortexStore(AndroidKeyValueStore(context)) }
}

private class AndroidKeyValueStore(context: Context) : KeyValueStore {
  private val prefs = context.getSharedPreferences("vortex_store", Context.MODE_PRIVATE)

  override fun getString(key: String): String? = prefs.getString(key, null)

  override fun putString(key: String, value: String) {
    prefs.edit { putString(key, value) }
  }
}
