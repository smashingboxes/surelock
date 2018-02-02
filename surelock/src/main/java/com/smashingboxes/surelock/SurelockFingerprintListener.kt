package com.smashingboxes.surelock

/**
 * Created by Tyler McCraw on 2/17/17.
 *
 *
 * Simple interface for handling fingerprint authentication events
 *
 */

interface SurelockFingerprintListener {

    /**
     * Handle successful fingerprint enrollment event
     */
    fun onFingerprintEnrolled()

    /**
     * Handle successful authentication event
     *
     * @param decryptedValue String which represents the decrypted bytes of the store value
     */
    fun onFingerprintAuthenticated(decryptedValue: ByteArray)

    /**
     * Handle error occurred during authentication
     *
     * @param errorMessage error message (use this for logging)
     */
    fun onFingerprintError(errorMessage: CharSequence?)
}