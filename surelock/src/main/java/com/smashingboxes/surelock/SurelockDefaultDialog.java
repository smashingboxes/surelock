package com.smashingboxes.surelock;

import android.app.Dialog;
import android.app.DialogFragment;
import android.app.FragmentManager;
import android.content.Context;
import android.content.res.TypedArray;
import android.hardware.fingerprint.FingerprintManager;
import android.os.Bundle;
import android.support.annotation.NonNull;
import android.support.annotation.StyleRes;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.view.Window;
import android.widget.Button;
import android.widget.TextView;

import com.mattprecious.swirl.SwirlView;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;

/**
 * Created by Tyler McCraw on 2/17/17.
 * <p>
 *     Default login dialog which uses fingerprint APIs to authenticate the user,
 *     and falls back to password authentication if fingerprint is not available.
 * </p>
 */

public class SurelockDefaultDialog extends DialogFragment implements SurelockFragment {

    private static final long ERROR_TIMEOUT_MILLIS = 1600;
    private static final long SUCCESS_DELAY_MILLIS = 1300; //TODO make these configurable via attrs

    private FingerprintManager fingerprintManager;
    private FingerprintManager.CryptoObject cryptoObject;
    private String keyForDecryption;
    private SurelockStorage storage;
    private SurelockFingerprintListener listener;
    private SurelockFingerprintUiHelper uiHelper;
    @StyleRes
    private int styleId;

    // TODO  clean up and genericize default dialog - add custom attribute set which can be overridden
    private SwirlView iconView;
    private TextView statusTextView;

    @Override
    public void init(FingerprintManager fingerprintManager,
                     FingerprintManager.CryptoObject cryptoObject,
                     @NonNull String key, SurelockStorage storage) {
        this.cryptoObject = cryptoObject;
        this.fingerprintManager = fingerprintManager;
        this.keyForDecryption = key;
        this.storage = storage;
    }

    /**
     * Sets the resource id of the style set to use for custom attributes
     *
     * @param styleId The resource id of the style set
     */
    public void setStyleId(@StyleRes int styleId) {
        this.styleId = styleId;
    }

    @Override
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        uiHelper = new SurelockFingerprintUiHelper(fingerprintManager, this);

        // Do not create a new Fragment when the Activity is re-created such as orientation changes.
        setRetainInstance(true);

        TypedArray attrs = getActivity().obtainStyledAttributes(styleId, R.styleable
                .SurelockDefaultDialog);
        int dialogTheme = attrs.getResourceId(R.styleable.SurelockDefaultDialog_sl_dialog_theme,
                Integer.MAX_VALUE);
        attrs.recycle();

        setStyle(DialogFragment.STYLE_NO_TITLE, dialogTheme == Integer.MAX_VALUE ? android.R.style
                .Theme : dialogTheme);
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
                .SurelockDefaultDialog_sl_fallback_button_background, Integer.MAX_VALUE);
        int fallbackButtonTextColor = attrs.getColor(R.styleable
                .SurelockDefaultDialog_sl_fallback_button_text_color, Integer.MAX_VALUE);
        fallbackButton.setText(fallbackButtonText);
        if (fallbackButtonColor != Integer.MAX_VALUE) {
            fallbackButton.setBackgroundColor(fallbackButtonColor);
        }
        if (fallbackButtonTextColor != Integer.MAX_VALUE) {
            fallbackButton.setTextColor(fallbackButtonTextColor);
        }

        TextView titleBar = (TextView) fragmentView.findViewById(R.id.sl_title_bar);
        String titleBarText = attrs.getString(R.styleable.SurelockDefaultDialog_sl_title_bar_text);
        titleBar.setText(titleBarText);
        int titleBarColor = attrs.getColor(R.styleable
                .SurelockDefaultDialog_sl_title_bar_background, Integer.MAX_VALUE);
        int titleBarTextColor = attrs.getColor(R.styleable
                .SurelockDefaultDialog_sl_title_bar_text_color, Integer.MAX_VALUE);
        if (titleBarColor != Integer.MAX_VALUE) {
            titleBar.setBackgroundColor(titleBarColor);
        }
        if (titleBarTextColor != Integer.MAX_VALUE) {
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
    public void onAuthenticationSucceeded(FingerprintManager.AuthenticationResult result) {
        iconView.postDelayed(new Runnable() {
            @Override
            public void run() {
                //TODO figure out a way to not make user have to run decryption themselves here
                byte[] encryptedValue = storage.get(keyForDecryption);
                byte[] decryptedValue;
                try {
                    decryptedValue = cryptoObject.getCipher().doFinal(encryptedValue);
                    listener.onFingerprintAuthenticated(decryptedValue);
                } catch (BadPaddingException | IllegalBlockSizeException e) {
                    listener.onFingerprintError(e.getMessage());
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
        statusTextView.setTextColor(getResources().getColor(R.color.error_red, null));
        statusTextView.removeCallbacks(resetErrorTextRunnable);
        statusTextView.postDelayed(resetErrorTextRunnable, ERROR_TIMEOUT_MILLIS);
    }

    private Runnable resetErrorTextRunnable = new Runnable() {
        @Override
        public void run() {
            if (isAdded()) {
                statusTextView.setTextColor(getResources().getColor(R.color.hint_grey, null));
                statusTextView.setText(getResources().getString(R.string.fingerprint_hint));
                iconView.setState(SwirlView.State.ON);
            }
        }
    };
}
