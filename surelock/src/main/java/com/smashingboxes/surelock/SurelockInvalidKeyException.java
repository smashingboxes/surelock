package com.smashingboxes.surelock;

/**
 * Created by Tyler McCraw on 4/3/17.
 * <p>
 *     KeyStore key was invalidated. This means you need to re-enroll the fingerprint
 *     via enrollFingerprintAndStore() or store() methods so that the value
 *     can be re-encrypted with a valid key.
 * </p>
 */

public class SurelockInvalidKeyException extends SurelockException {

    public SurelockInvalidKeyException(String message, Throwable cause) {
        super(message, cause);
    }
}
