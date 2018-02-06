package com.smashingboxes.surelock

/**
 * Created by Tyler McCraw on 3/5/17.
 *
 *
 * Exception for any issues in setting up Surelock
 * dependencies for encryption/decryption using FingerprintManager
 *
 */
open class SurelockException(message: String, cause: Throwable?) : RuntimeException(message, cause)
