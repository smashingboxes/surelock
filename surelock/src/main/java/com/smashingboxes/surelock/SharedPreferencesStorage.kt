package com.smashingboxes.surelock

import android.content.Context
import android.content.SharedPreferences
import android.text.TextUtils
import android.util.Base64
import java.util.*

/**
 * Created by Tyler McCraw on 3/5/17.
 *
 *
 * Storage mechanism used by Surelock in order to
 * persist encrypted objects in SharedPreferences by default
 *
 */

class SharedPreferencesStorage
/**
 * Create a new SurelockStorage which uses SharedPreferences for persistence
 *
 * @param context context
 * @param prefsName Desired preferences file.
 */
(private val context: Context, private val prefsName: String) : SurelockStorage {

    private var preferences: SharedPreferences? = null

    private val prefs: SharedPreferences
        @Synchronized get() {
            if (preferences == null) {
                preferences = context.getSharedPreferences(prefsName, Context.MODE_PRIVATE)
            }
            return preferences!!
        }

    override fun createOrUpdate(key: String, objectToStore: ByteArray) {
        val encodedString = Base64.encodeToString(objectToStore, Base64.DEFAULT)
        prefs.edit().putString(key, encodedString).apply()
    }

    override fun get(key: String): ByteArray? {
        val byteString = prefs.getString(key, null)
        var decodedBytes: ByteArray? = null
        if (!TextUtils.isEmpty(byteString)) {
            decodedBytes = Base64.decode(byteString, Base64.DEFAULT)
        }
        return decodedBytes
    }

    override fun remove(key: String) {
        prefs.edit().remove(key).apply()
    }

    override fun clearAll() {
        prefs.edit().clear().apply()
    }

    override val keys: Set<String>?
        get() = Collections.unmodifiableSet(LinkedHashSet(prefs.all.keys))
}
