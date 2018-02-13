package com.smashingboxes.surelock

import android.support.v4.app.FragmentManager
import android.support.v4.hardware.fingerprint.FingerprintManagerCompat

/**
 * Created by Tyler McCraw on 2/17/17.
 *
 *
 * Implement this interface in your custom Fragment or DialogFragment
 * to customize your own lock screen and then pass your
 * implemented Surelock dialog to [Surelock] loginWithFingerprint()
 *
 */

interface SurelockFragment {

    /**
     * Set up the fragment
     * NOTE: This must be called before show()
     *
     * @param fingerprintManager an instance of FingerprintManager
     * @param cryptoObject the CryptoObject which wraps the cipher used for encryption/decryption
     * @param key pointer in storage to encrypted value that will be used for this session's decryption
     * @param storage instance of SurelockStorage to be used for decrypting the value at the specified key
     * @param valueToEncrypt The value to encrypt in storage
     */
    fun init(fingerprintManager: FingerprintManagerCompat,
             cryptoObject: FingerprintManagerCompat.CryptoObject, key: String,
             storage: SurelockStorage, valueToEncrypt: ByteArray?)

    /**
     * Display the fragment
     * You may want to check if it's already displayed here
     * TODO check if this works for plain Fragments as well and not just DialogFragments
     *
     * @param fragmentManager an instance of FragmentManager
     * @param fingerprintDialogFragmentTag a tag used for keeping track of the fragment's display state
     */
    fun show(fragmentManager: FragmentManager, fingerprintDialogFragmentTag: String)

    /**
     * Called when an unrecoverable error has been encountered and the operation is complete.
     * No further callbacks will be made on this object.
     *
     * @param errorCode An integer identifying the error message
     * @param errString A human-readable error string that can be shown in UI
     */
    fun onAuthenticationError(errorCode: Int, errString: CharSequence?)

    /**
     * Called when a recoverable error has been encountered during authentication. The help
     * string is provided to give the user guidance for what went wrong, such as
     * "Sensor dirty, please clean it."
     *
     * @param helpCode An integer identifying the error message
     * @param helpString A human-readable string that can be shown in UI
     */
    fun onAuthenticationHelp(helpCode: Int, helpString: CharSequence?)

    /**
     * Called when a fingerprint is recognized.
     *
     * @param result An object containing authentication-related data
     */
    fun onAuthenticationSucceeded(result: FingerprintManagerCompat.AuthenticationResult?)

    /**
     * Called when a fingerprint is valid but not recognized.
     */
    fun onAuthenticationFailed()
}
