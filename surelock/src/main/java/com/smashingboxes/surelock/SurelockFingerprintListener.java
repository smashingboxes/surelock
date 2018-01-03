package com.smashingboxes.surelock;

import android.support.annotation.Nullable;

/**
 * Created by Tyler McCraw on 2/17/17.
 * <p>
 *     Simple interface for handling fingerprint authentication events
 * </p>
 */

public interface SurelockFingerprintListener {

    /**
     * Handle successful fingerprint enrollment event
     */
    void onFingerprintEnrolled();

    /**
     * Handle successful authentication event
     *
     * @param decryptedValue String which represents the decrypted bytes of the store value
     */
    void onFingerprintAuthenticated(byte[] decryptedValue);

    /**
     * Handle error occurred during authentication
     *
     * @param errorMessage error message (use this for logging)
     */
    void onFingerprintError(@Nullable CharSequence errorMessage);
}