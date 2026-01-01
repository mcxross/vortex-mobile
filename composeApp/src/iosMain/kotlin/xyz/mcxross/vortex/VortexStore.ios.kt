package xyz.mcxross.vortex.vortex

import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import platform.Foundation.NSUserDefaults

@Composable
actual fun rememberVortexStore(): VortexStore {
  return remember { VortexStore(IosKeyValueStore()) }
}

private class IosKeyValueStore : KeyValueStore {
  private val defaults = NSUserDefaults.standardUserDefaults()

  override fun getString(key: String): String? = defaults.stringForKey(key)

  override fun putString(key: String, value: String) {
    defaults.setObject(value, forKey = key)
  }
}
