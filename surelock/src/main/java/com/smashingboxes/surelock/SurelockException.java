package com.smashingboxes.surelock;

/**
 * Created by Tyler McCraw on 3/5/17.
 * <p>
 *     Exception for any issues in setting up Surelock
 *     dependencies for encryption/decryption using FingerprintManager
 * </p>
 */

public class SurelockException extends RuntimeException {

    public SurelockException(String message, Throwable cause) {
        super(message, cause);
    }
}
