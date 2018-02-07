package com.smashingboxes.surelock

import android.support.annotation.CheckResult

/**
 * Created by Tyler McCraw on 3/5/17.
 *
 *
 * Persistence management interface required for Surelock
 * to store encrypted objects based on fingerprint authentication
 *
 */

interface SurelockStorage {

    @get:CheckResult
    val keys: Set<String>?

    fun createOrUpdate(key: String, objectToStore: ByteArray)

    @CheckResult
    operator fun get(key: String): ByteArray?

    fun remove(key: String)

    fun clearAll()
}
