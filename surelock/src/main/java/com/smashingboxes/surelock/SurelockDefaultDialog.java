package com.smashingboxes.surelock;

import android.app.Dialog;
import android.app.DialogFragment;
import android.app.FragmentManager;
import android.content.Context;
import android.content.res.TypedArray;
import android.os.Bundle;
import android.support.annotation.NonNull;
import android.support.annotation.StyleRes;
import android.support.v4.content.ContextCompat;
import android.support.v4.hardware.fingerprint.FingerprintManagerCompat;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.view.Window;
import android.widget.Button;
import android.widget.TextView;

import com.mattprecious.swirl.SwirlView;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;

/**
 * Created by Tyler McCraw on 2/17/17.
 * <p>
 *     Default login dialog which uses fingerprint APIs to authenticate the user,
 *     and falls back to password authentication if fingerprint is not available.
 * </p>
 */

public class SurelockDefaultDialog extends DialogFragment implements SurelockFragment {

    private static final String KEY_CIPHER_OP_MODE = "com.smashingboxes.surelock.SurelockDefaultDialog.KEY_CIPHER_OP_MODE";
    private static final String KEY_STYLE_ID = "com.smashingboxes.surelock.KEY_STYLE_ID";

    private static final long ERROR_TIMEOUT_MILLIS = 1600;
    private static final long SUCCESS_DELAY_MILLIS = 1300; //TODO make these configurable via attrs

    private FingerprintManagerCompat fingerprintManager;
    private FingerprintManagerCompat.CryptoObject cryptoObject;
    private String keyForDecryption;
    private byte[] valueToEncrypt;
    private SurelockStorage storage;
    private SurelockFingerprintListener listener;
    private SurelockFingerprintUiHelper uiHelper;
    private int cipherOperationMode;
    @StyleRes
    private int styleId;

    // TODO  clean up and genericize default dialog - add custom attribute set which can be overridden
    private SwirlView iconView;
    private TextView statusTextView;

    static SurelockDefaultDialog newInstance(int cipherOperationMode,
                                                    @StyleRes int styleId) {
        Bundle args = new Bundle();
        args.putInt(KEY_CIPHER_OP_MODE, cipherOperationMode);
        args.putInt(KEY_STYLE_ID, styleId);

        SurelockDefaultDialog fragment = new SurelockDefaultDialog();
        fragment.setArguments(args);

        return fragment;
    }

    @Override
    public void init(FingerprintManagerCompat fingerprintManager,
                     FingerprintManagerCompat.CryptoObject cryptoObject,
                     @NonNull String key, SurelockStorage storage, byte[] valueToEncrypt) {
        this.cryptoObject = cryptoObject;
        this.fingerprintManager = fingerprintManager;
        this.keyForDecryption = key; //TODO need to be passing these as newInstance params... or figure a better way to do this
        this.storage = storage;
        this.valueToEncrypt = valueToEncrypt;
    }

    @Override
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        uiHelper = new SurelockFingerprintUiHelper(fingerprintManager, this);

        // Do not create a new Fragment when the Activity is re-created such as orientation changes.
        setRetainInstance(true);

        if (savedInstanceState != null) {
            cipherOperationMode = savedInstanceState.getInt(KEY_CIPHER_OP_MODE);
            styleId = savedInstanceState.getInt(KEY_STYLE_ID);
        } else {
            cipherOperationMode = getArguments().getInt(KEY_CIPHER_OP_MODE);
            styleId = getArguments().getInt(KEY_STYLE_ID);
        }

        TypedArray attrs = getActivity().obtainStyledAttributes(styleId, R.styleable
                .SurelockDefaultDialog);
        int dialogTheme = attrs.getResourceId(R.styleable.SurelockDefaultDialog_sl_dialog_theme, 0);
        attrs.recycle();

        setStyle(DialogFragment.STYLE_NO_TITLE, dialogTheme == 0 ? R.style
                .SurelockTheme_NoActionBar : dialogTheme);
    }

    @Override
    public View onCreateView(LayoutInflater inflater, ViewGroup container, Bundle
            savedInstanceState) {
        View view = inflater.inflate(R.layout.fingerprint_dialog_container, container, false);
        TypedArray attrs = getActivity().obtainStyledAttributes(styleId, R.styleable
                .SurelockDefaultDialog);

        setUpViews(view, attrs);

        attrs.recycle();

        return view;
    }

    private void setUpViews(View fragmentView, TypedArray attrs) {
        iconView = (SwirlView) fragmentView.findViewById(R.id.fingerprint_icon);
        statusTextView = (TextView) fragmentView.findViewById(R.id.fingerprint_status);
        Button fallbackButton = (Button) fragmentView.findViewById(R.id.fallback_button);
        fallbackButton.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                dismiss();
            }
        });

        String fallbackButtonText = attrs.getString(R.styleable
                .SurelockDefaultDialog_sl_fallback_button_text);
        int fallbackButtonColor = attrs.getColor(R.styleable
                .SurelockDefaultDialog_sl_fallback_button_background, 0);
        int fallbackButtonTextColor = attrs.getColor(R.styleable
                .SurelockDefaultDialog_sl_fallback_button_text_color, 0);
        fallbackButton.setText(fallbackButtonText);
        if (fallbackButtonColor != 0) {
            fallbackButton.setBackgroundColor(fallbackButtonColor);
        }
        if (fallbackButtonTextColor != 0) {
            fallbackButton.setTextColor(fallbackButtonTextColor);
        }

        TextView titleBar = (TextView) fragmentView.findViewById(R.id.sl_title_bar);
        String titleBarText = attrs.getString(R.styleable.SurelockDefaultDialog_sl_title_bar_text);
        titleBar.setText(titleBarText);
        int titleBarColor = attrs.getColor(R.styleable
                .SurelockDefaultDialog_sl_title_bar_background, 0);
        int titleBarTextColor = attrs.getColor(R.styleable
                .SurelockDefaultDialog_sl_title_bar_text_color, 0);
        if (titleBarColor != 0) {
            titleBar.setBackgroundColor(titleBarColor);
        }
        if (titleBarTextColor != 0) {
            titleBar.setTextColor(titleBarTextColor);
        }

    }

    @Override
    public Dialog onCreateDialog(final Bundle savedInstanceState) {
        final Dialog dialog = super.onCreateDialog(savedInstanceState);
        dialog.requestWindowFeature(Window.FEATURE_NO_TITLE);
        return dialog;
    }

    @Override
    public void onAttach(Context context) {
        super.onAttach(context);
        if (context instanceof SurelockFingerprintListener) {
            listener = (SurelockFingerprintListener) context;
        } else {
            throw new RuntimeException(context.toString()
                    + " must implement SurelockFingerprintListener");
        }
    }

    @Override
    public void onResume() {
        super.onResume();
        uiHelper.startListening(cryptoObject);
        iconView.setState(SwirlView.State.ON);
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
        outState.putInt(KEY_STYLE_ID, styleId);
        super.onSaveInstanceState(outState);
    }

    @Override
    public void onAuthenticationSucceeded(FingerprintManagerCompat.AuthenticationResult result) {
        iconView.postDelayed(new Runnable() {
            @Override
            public void run() {
                //TODO figure out a way to not make user have to run encryption/decryption themselves here
                if (Cipher.ENCRYPT_MODE == cipherOperationMode) {
                    try {
                        final byte[] encryptedValue = cryptoObject.getCipher().doFinal(valueToEncrypt);
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
    public void onAuthenticationFailed() {
        showError(statusTextView.getResources().getString(R.string.fingerprint_not_recognized));
        listener.onFingerprintError(null);
    }

    private void showError(CharSequence error) {
        iconView.setState(SwirlView.State.ERROR);
        statusTextView.setText(error);
        statusTextView.setTextColor(ContextCompat.getColor(getActivity(), R.color.error_red));
        statusTextView.removeCallbacks(resetErrorTextRunnable);
        statusTextView.postDelayed(resetErrorTextRunnable, ERROR_TIMEOUT_MILLIS);
    }

    private Runnable resetErrorTextRunnable = new Runnable() {
        @Override
        public void run() {
            if (isAdded()) {
                statusTextView.setTextColor(ContextCompat.getColor(getActivity(), R.color.hint_grey));
                statusTextView.setText(getResources().getString(R.string.fingerprint_hint));
                iconView.setState(SwirlView.State.ON);
            }
        }
    };
}
