package com.smashingboxes.surelock

import android.support.v4.hardware.fingerprint.FingerprintManagerCompat
import android.support.v4.os.CancellationSignal

/**
 * Created by Tyler McCraw on 2/17/17.
 *
 *
 * Manage fingerprint authentication UI by listening to
 * Handles forwarding callbacks from the FingerprintManager
 *
 */

class SurelockFingerprintUiHelper internal constructor(
    private val fingerprintManager: FingerprintManagerCompat,
    private val callback: SurelockFragment) : FingerprintManagerCompat.AuthenticationCallback() {
    private var cancellationSignal: CancellationSignal? = null
    private var selfCancelled: Boolean = false

    fun startListening(cryptoObject: FingerprintManagerCompat.CryptoObject) {
        cancellationSignal = CancellationSignal()
        selfCancelled = false

        //TODO pass in a handler here for background authentication?
        //TODO take a look at per-user FingerprintManager.authenticate(..., userId) call
        // noinspection ResourceType
        fingerprintManager.authenticate(cryptoObject, 0 /* flags */, cancellationSignal, this, null)
    }

    fun stopListening() {
        cancellationSignal?.let {
            selfCancelled = true
            it.cancel()
            cancellationSignal = null
        }
    }

    override fun onAuthenticationError(errMsgId: Int, errString: CharSequence?) {
        if (!selfCancelled) {
            callback.onAuthenticationError(errMsgId, errString)
        }
    }

    override fun onAuthenticationHelp(helpMsgId: Int, helpString: CharSequence?) {
        callback.onAuthenticationHelp(helpMsgId, helpString)
    }

    override fun onAuthenticationFailed() {
        callback.onAuthenticationFailed()
    }

    override fun onAuthenticationSucceeded(result: FingerprintManagerCompat.AuthenticationResult?) {
        callback.onAuthenticationSucceeded(result)
    }
}