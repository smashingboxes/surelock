package com.smashingboxes.surelock;

import android.support.v4.hardware.fingerprint.FingerprintManagerCompat;
import android.support.v4.os.CancellationSignal;

/**
 * Created by Tyler McCraw on 2/17/17.
 * <p>
 *     Manage fingerprint authentication UI by listening to
 *     Handles forwarding callbacks from the FingerprintManager
 * </p>
 */

public class SurelockFingerprintUiHelper extends FingerprintManagerCompat.AuthenticationCallback {

    private final FingerprintManagerCompat fingerprintManager;
    private final SurelockFragment callback;
    private CancellationSignal cancellationSignal;
    private boolean selfCancelled;

    SurelockFingerprintUiHelper(FingerprintManagerCompat fingerprintManager, SurelockFragment callback) {
        this.fingerprintManager = fingerprintManager;
        this.callback = callback;
    }

    public void startListening(FingerprintManagerCompat.CryptoObject cryptoObject) {
        cancellationSignal = new CancellationSignal();
        selfCancelled = false;

        //TODO pass in a handler here for background authentication?
        //TODO take a look at per-user FingerprintManager.authenticate(..., userId) call
        // noinspection ResourceType
        fingerprintManager.authenticate(cryptoObject, 0 /* flags */, cancellationSignal, this, null);
    }

    public void stopListening() {
        if (cancellationSignal != null) {
            selfCancelled = true;
            cancellationSignal.cancel();
            cancellationSignal = null;
        }
    }

    @Override
    public void onAuthenticationError(int errMsgId, CharSequence errString) {
        if (!selfCancelled) {
            callback.onAuthenticationError(errMsgId, errString);
        }
    }

    @Override
    public void onAuthenticationHelp(int helpMsgId, CharSequence helpString) {
        callback.onAuthenticationHelp(helpMsgId, helpString);
    }

    @Override
    public void onAuthenticationFailed() {
        callback.onAuthenticationFailed();
    }

    @Override
    public void onAuthenticationSucceeded(FingerprintManagerCompat.AuthenticationResult result) {
        callback.onAuthenticationSucceeded(result);
    }
}