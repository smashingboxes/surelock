package com.smashingboxes.surelock;

import android.app.DialogFragment;
import android.app.FragmentManager;
import android.content.Context;
import android.os.Bundle;
import android.support.annotation.NonNull;
import android.support.annotation.Nullable;
import android.support.v4.content.ContextCompat;
import android.support.v4.hardware.fingerprint.FingerprintManagerCompat;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.Button;
import android.widget.TextView;

import com.mattprecious.swirl.SwirlView;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;

/**
 * Created by Nicholas Cook on 3/17/17.
 * <p>
 *     A login dialog which follows standard Material Design guidelines. It uses
 *     fingerprint APIs to authenticate the user, and falls back to password
 *     authentication if fingerprint is not available.
 * </p>
 */

public class SurelockMaterialDialog extends DialogFragment implements SurelockFragment {

    private static final String KEY_CIPHER_OP_MODE = "com.smashingboxes.surelock" +
            ".SurelockMaterialDialog.KEY_CIPHER_OP_MODE";

    private SwirlView swirlView;
    private TextView messageView;

    private FingerprintManagerCompat fingerprintManager;
    private FingerprintManagerCompat.CryptoObject cryptoObject;
    private String keyForDecryption;
    private byte[] valueToEncrypt;
    private SurelockStorage storage;
    private SurelockFingerprintListener listener;
    private SurelockFingerprintUiHelper uiHelper;
    private int cipherOperationMode;

    private static final long ERROR_TIMEOUT_MILLIS = 1600;
    private static final long SUCCESS_DELAY_MILLIS = 1300;

    static SurelockMaterialDialog newInstance(int cipherOperationMode) {

        Bundle args = new Bundle();
        args.putInt(KEY_CIPHER_OP_MODE, cipherOperationMode);

        SurelockMaterialDialog fragment = new SurelockMaterialDialog();
        fragment.setArguments(args);
        return fragment;
    }

    @Override
    public void onAttach(Context context) {
        super.onAttach(context);
        if (context instanceof SurelockFingerprintListener) {
            listener = (SurelockFingerprintListener) context;
        } else {
            throw new RuntimeException(context.toString() + " must implement " +
                    "SurelockFingerprintListener");
        }
    }

    @Override
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        uiHelper = new SurelockFingerprintUiHelper(fingerprintManager, this);

        // Do not create a new Fragment when the Activity is re-created such as orientation changes.
        setRetainInstance(true);

        if (savedInstanceState != null) {
            cipherOperationMode = savedInstanceState.getInt(KEY_CIPHER_OP_MODE);
        } else {
            cipherOperationMode = getArguments().getInt(KEY_CIPHER_OP_MODE);
        }

        setStyle(DialogFragment.STYLE_NORMAL, android.R.style.Theme_Material_Light_Dialog);
    }

    @Nullable
    @Override
    public View onCreateView(LayoutInflater inflater, @Nullable ViewGroup container, Bundle
            savedInstanceState) {
        getDialog().setTitle(R.string.sl_sign_in);
        View view = inflater.inflate(R.layout.material_fingerprint_dialog, container, false);
        Button cancelButton = (Button) view.findViewById(R.id.cancel_button);
        cancelButton.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                dismiss();
            }
        });
        swirlView = (SwirlView) view.findViewById(R.id.fingerprint_icon);
        messageView = (TextView) view.findViewById(R.id.fingerprint_status);
        return view;
    }

    @Override
    public void onResume() {
        super.onResume();
        uiHelper.startListening(cryptoObject);
        swirlView.setState(SwirlView.State.ON);
    }

    @Override
    public void show(FragmentManager manager, String tag) {
        if (getDialog() == null || !getDialog().isShowing()) {
            super.show(manager, tag);
        }
    }

    @Override
    public void onPause() {
        super.onPause();
        uiHelper.stopListening();
    }

    @Override
    public void onDetach() {
        super.onDetach();
        listener = null;
    }

    @Override
    public void onSaveInstanceState(Bundle outState) {
        outState.putInt(KEY_CIPHER_OP_MODE, cipherOperationMode);
        super.onSaveInstanceState(outState);
    }

    @Override
    public void init(FingerprintManagerCompat fingerprintManager, FingerprintManagerCompat.CryptoObject
            cryptoObject, @NonNull String key, SurelockStorage storage, byte[] valueToEncrypt) {
        this.fingerprintManager = fingerprintManager;
        this.cryptoObject = cryptoObject;
        this.keyForDecryption = key;
        this.storage = storage;
        this.valueToEncrypt = valueToEncrypt;
    }

    @Override
    public void onAuthenticationError(int errorCode, CharSequence errString) {
        showError(errString);
        listener.onFingerprintError(errString);
        dismiss();
    }

    @Override
    public void onAuthenticationHelp(int helpCode, CharSequence helpString) {
        showError(helpString);
        listener.onFingerprintError(helpString);
    }

    @Override
    public void onAuthenticationSucceeded(FingerprintManagerCompat.AuthenticationResult result) {
        swirlView.postDelayed(new Runnable() {
            @Override
            public void run() {
                //TODO figure out a way to not make user have to run encryption/decryption
                // themselves here
                if (Cipher.ENCRYPT_MODE == cipherOperationMode) {
                    try {
                        final byte[] encryptedValue = cryptoObject.getCipher().doFinal
                                (valueToEncrypt);
                        storage.createOrUpdate(keyForDecryption, encryptedValue);
                        listener.onFingerprintEnrolled();
                    } catch (IllegalBlockSizeException | BadPaddingException e) {
                        listener.onFingerprintError(e.getMessage());
                    }
                } else if (Cipher.DECRYPT_MODE == cipherOperationMode) {
                    byte[] encryptedValue = storage.get(keyForDecryption);
                    byte[] decryptedValue;
                    try {
                        decryptedValue = cryptoObject.getCipher().doFinal(encryptedValue);
                        listener.onFingerprintAuthenticated(decryptedValue);
                    } catch (BadPaddingException | IllegalBlockSizeException e) {
                        listener.onFingerprintError(e.getMessage());
                    }
                }
                dismiss();
            }
        }, SUCCESS_DELAY_MILLIS);
    }

    @Override
    public void onAuthenticationFailed() {
        showError(messageView.getResources().getString(R.string.fingerprint_not_recognized));
        listener.onFingerprintError(null);
    }

    private void showError(CharSequence error) {
        swirlView.setState(SwirlView.State.ERROR);
        messageView.setText(error);
        messageView.setTextColor(ContextCompat.getColor(getActivity(), R.color.error_red));
        messageView.removeCallbacks(resetErrorTextRunnable);
        messageView.postDelayed(resetErrorTextRunnable, ERROR_TIMEOUT_MILLIS);
    }

    private Runnable resetErrorTextRunnable = new Runnable() {
        @Override
        public void run() {
            if (isAdded()) {
                messageView.setTextColor(ContextCompat.getColor(getActivity(), R.color.hint_grey));
                messageView.setText(getResources().getString(R.string.fingerprint_hint));
                swirlView.setState(SwirlView.State.ON);
            }
        }
    };
}
