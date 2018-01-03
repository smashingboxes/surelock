package com.smashingboxes.surelockdemo;

import android.animation.Animator;
import android.animation.AnimatorListenerAdapter;
import android.content.Context;
import android.content.DialogInterface;
import android.content.SharedPreferences;
import android.os.AsyncTask;
import android.os.Bundle;
import android.support.annotation.NonNull;
import android.support.annotation.Nullable;
import android.support.design.widget.TextInputEditText;
import android.support.design.widget.TextInputLayout;
import android.support.v7.app.AlertDialog;
import android.support.v7.app.AppCompatActivity;
import android.text.TextUtils;
import android.util.Log;
import android.view.KeyEvent;
import android.view.View;
import android.view.View.OnClickListener;
import android.view.inputmethod.EditorInfo;
import android.widget.Button;
import android.widget.CheckBox;
import android.widget.TextView;
import android.widget.Toast;

import com.smashingboxes.surelock.SharedPreferencesStorage;
import com.smashingboxes.surelock.Surelock;
import com.smashingboxes.surelock.SurelockException;
import com.smashingboxes.surelock.SurelockFingerprintListener;
import com.smashingboxes.surelock.SurelockInvalidKeyException;
import com.smashingboxes.surelock.SurelockStorage;

import java.io.UnsupportedEncodingException;

/**
 * Created by Tyler McCraw on 2/17/17.
 * <p>
 *     A login screen that offers login via username/password
 *     along with the option to set up future fingerprint authentication.
 * </p>
 */

public class LoginActivity extends AppCompatActivity implements SurelockFingerprintListener {

    private static final String TAG = LoginActivity.class.getSimpleName();
    private static final String FINGERPRINT_DIALOG_FRAGMENT_TAG = "com.smashingboxes.surelockdemo.FINGERPRINT_DIALOG_FRAGMENT_TAG";
    private static final String KEYSTORE_KEY_ALIAS = "com.smashingboxes.surelockdemo.KEYSTORE_KEY_ALIAS";
    private static final String KEY_CRE_DEN_TIALS = "com.smashingboxes.surelockdemo.KEY_CRE_DEN_TIALS";
    private static final String SHARED_PREFS_FILE_NAME = "surelock_demo_prefs";

    private UserLoginTask authTask = null;
    private Surelock surelock;
    private SurelockStorage surelockStorage;
    private SharedPreferences preferences;

    private TextInputEditText usernameView;
    private TextInputLayout usernameInputLayout;
    private TextInputEditText passwordView;
    private TextInputLayout passwordInputLayout;
    private CheckBox fingerprintCheckbox;
    private View progressView;
    private View loginFormView;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_login);
        surelockStorage = new SharedPreferencesStorage(this, SHARED_PREFS_FILE_NAME);
        setUpViews();
    }

    private void setUpViews() {
        usernameView = (TextInputEditText) findViewById(R.id.username);
        usernameInputLayout = (TextInputLayout) findViewById(R.id.username_input_layout);
        passwordView = (TextInputEditText) findViewById(R.id.password);
        passwordInputLayout = (TextInputLayout) findViewById(R.id.password_input_layout);
        fingerprintCheckbox = (CheckBox) findViewById(R.id.fingerprint_checkbox);
        loginFormView = findViewById(R.id.login_form);
        progressView = findViewById(R.id.login_progress);

        passwordView.setOnEditorActionListener(new TextView.OnEditorActionListener() {
            @Override
            public boolean onEditorAction(TextView textView, int id, KeyEvent keyEvent) {
                if (id == R.id.login || id == EditorInfo.IME_NULL) {
                    handleLoginClick();
                    return true;
                }
                return false;
            }
        });

        Button signInButton = (Button) findViewById(R.id.sign_in_button);
        signInButton.setOnClickListener(new OnClickListener() {
            @Override
            public void onClick(View view) {
                handleLoginClick();
            }
        });
    }

    @Override
    protected void onResume() {
        super.onResume();
        if (userWantsToUseFingerprintToLogin()) {
            if (!Surelock.fingerprintAuthIsSetUp(this, true)) {
                fingerprintCheckbox.setVisibility(View.VISIBLE);
                fingerprintCheckbox.setChecked(false);
            } else {
                try {
                    getSurelock().loginWithFingerprint(KEY_CRE_DEN_TIALS);
                } catch (SurelockInvalidKeyException e) {
                    surelockStorage.clearAll();
                    showFingerprintLoginInvalidated();
                }
                fingerprintCheckbox.setVisibility(View.GONE);
            }
        }
    }

    private Surelock getSurelock() {
        if (surelock == null) {
            surelock = new Surelock.Builder(this)
                    .withDefaultDialog(R.style.SurelockDemoDialog)
                    .withKeystoreAlias(KEYSTORE_KEY_ALIAS)
                    .withFragmentManager(getFragmentManager())
                    .withSurelockFragmentTag(FINGERPRINT_DIALOG_FRAGMENT_TAG)
                    .withSurelockStorage(surelockStorage)
                    .build();
        }
        return surelock;
    }

    private void showFingerprintLoginInvalidated() {
        AlertDialog.Builder dialog = new AlertDialog.Builder(this);
        dialog.setTitle(R.string.sl_login_error)
                .setMessage(R.string.sl_re_enroll)
                .setPositiveButton(android.R.string.ok, new DialogInterface.OnClickListener() {
                    @Override
                    public void onClick(DialogInterface dialog, int which) {
                        dialog.dismiss();
                    }
                }).show();
    }

    @NonNull
    private SharedPreferences getPreferenceHelper() {
        if (preferences == null) {
            preferences = getSharedPreferences(SHARED_PREFS_FILE_NAME, Context.MODE_PRIVATE);
        }
        return preferences;
    }

    private boolean userWantsToUseFingerprintToLogin() {
        return getPreferenceHelper().contains(KEY_CRE_DEN_TIALS);
    }

    private boolean validateLoginForm(String username, String password) {
        boolean errorsExist = false;
        View focusView = null;

        if (TextUtils.isEmpty(username)) {
            usernameInputLayout.setError(getString(R.string.error_field_required));
            focusView = usernameView;
            errorsExist = true;
        } else {
            usernameInputLayout.setError(null);
        }

        if (TextUtils.isEmpty(password)) {
            passwordInputLayout.setError(getString(R.string.error_field_required));
            focusView = passwordView;
            errorsExist = true;
        } else {
            passwordInputLayout.setError(null);
        }

        if (errorsExist) {
            focusView.requestFocus();
        }
        return errorsExist;
    }

    private void handleLoginClick() {
        String username = usernameView.getText().toString();
        String password = passwordView.getText().toString();

        if (fingerprintCheckbox.isChecked() && Surelock.fingerprintAuthIsSetUp(this, true)) {
            attemptLoginForFingerprintEnrollment(username, password);
        } else {
            attemptLogin(username, password);
        }
    }

    private void attemptLogin(String username, String password) {
        // Don't allow multiple login attempts in a row
        if (authTask != null) {
            return;
        }

        if (!validateLoginForm(username, password)) {
            showProgress(true);
            authTask = new UserLoginTask(false);
            //We're just fetching this to show you on the next screen for demo purposes.
            String storedEncryptedValueString = "";
            try {
                byte[] storedEncryptedValue = surelockStorage.get(KEY_CRE_DEN_TIALS);
                if (storedEncryptedValue != null) {
                    storedEncryptedValueString = new String(storedEncryptedValue, "UTF-8");
                }
            } catch (UnsupportedEncodingException e) {
                Log.d(TAG, "attemptLogin: cannot fetch encrypted credentials");
            }
            authTask.execute(
                    usernameView.getText().toString(), passwordView.getText().toString(),
                    storedEncryptedValueString,
                    username, password);
        }
    }

    private void attemptLoginForFingerprintEnrollment(String username, String password) {
        // Don't allow multiple login attempts in a row
        if (authTask != null) {
            return;
        }

        if (!validateLoginForm(username, password)) {
            showProgress(true);
            authTask = new UserLoginTask(true);
            authTask.execute(usernameView.getText().toString(), passwordView.getText().toString());
        }
    }


    private void showProgress(final boolean show) {
        if (loginFormView != null && progressView != null) {
            int shortAnimTime = getResources().getInteger(android.R.integer.config_shortAnimTime);

            loginFormView.setVisibility(show ? View.GONE : View.VISIBLE);
            loginFormView.animate()
                    .setDuration(shortAnimTime)
                    .alpha(show ? 0 : 1)
                    .setListener(new AnimatorListenerAdapter() {
                        @Override
                        public void onAnimationEnd(Animator animation) {
                            loginFormView.setVisibility(show ? View.GONE : View.VISIBLE);
                        }
                    });

            progressView.setVisibility(show ? View.VISIBLE : View.GONE);
            progressView.animate()
                    .setDuration(shortAnimTime)
                    .alpha(show ? 1 : 0)
                    .setListener(new AnimatorListenerAdapter() {
                        @Override
                        public void onAnimationEnd(Animator animation) {
                            progressView.setVisibility(show ? View.VISIBLE : View.GONE);
                        }
                    });
        }
    }

    /**
     * Represents an asynchronous login/registration task
     * used to authenticate the user.
     */
    private class UserLoginTask extends AsyncTask<String, Void, String[]> {

        private boolean withFingerprintEnrollment;

        public UserLoginTask(boolean withFingerprintEnrollment) {
            this.withFingerprintEnrollment = withFingerprintEnrollment;
        }

        @Override
        protected String[] doInBackground(String... params) {
            try {
                // You should add your network call to authenticate here.
                // This just "simulates" network access.
                Thread.sleep(2000);
            } catch (InterruptedException e) {
                Log.e(TAG, "doInBackground: auth task failed", e);
            }
            if (withFingerprintEnrollment) {
                return new String[]{params[0], params[1]};
            } else {
                return new String[]{params[0], params[1], params[2], params[3], params[4]};
            }
        }

        @Override
        protected void onPostExecute(String... params) {
            authTask = null;
            showProgress(false);
            if (withFingerprintEnrollment) {
                try {
                    getSurelock().enrollFingerprintAndStore(KEY_CRE_DEN_TIALS,
                            getFormattedCredentialsForEncryption(params[0], params[1]));
                } catch (UnsupportedEncodingException e) {
                    Toast.makeText(LoginActivity.this, "Failed to encrypt the login", Toast.LENGTH_LONG).show();
                    Log.e(TAG, "Failed to encrypt the login" + e.getMessage());
                } catch (SurelockException e) {
                    Toast.makeText(LoginActivity.this, e.getMessage(), Toast.LENGTH_LONG).show();
                }
            } else {
                MainActivity.start(LoginActivity.this, params[0], params[1], params[2], params[3], params[4]);
            }
        }

        @Override
        protected void onCancelled() {
            authTask = null;
            showProgress(false);
        }
    }

    ///////////////////////////////////////////////////////////////////////////
    // FINGERPRINT AUTH
    ///////////////////////////////////////////////////////////////////////////

    @Override
    public void onFingerprintEnrolled() {
        //We're just fetching this to show you on the next screen for demo purposes.
        String storedEncryptedValueString = "";
        try {
            byte[] storedEncryptedValue = surelockStorage.get(KEY_CRE_DEN_TIALS);
            if (storedEncryptedValue != null) {
                storedEncryptedValueString = new String(storedEncryptedValue, "UTF-8");
            }
        } catch (UnsupportedEncodingException e) {
            Log.d(TAG, "attemptLogin: cannot fetch encrypted credentials");
        }
        MainActivity.start(LoginActivity.this, usernameView.getText().toString(), passwordView.getText().toString(),
                storedEncryptedValueString, usernameView.getText().toString(), passwordView.getText().toString());
    }

    @Override
    public void onFingerprintAuthenticated(byte[] decryptedValue) {
        String username = null;
        String password = null;

        try {
            String decryptedString = new String(decryptedValue, "UTF-8");
            if (!TextUtils.isEmpty(decryptedString)) {
                username = getUsernameFromFormattedCredentials(decryptedString);
                password = getPasswordFromFormattedCredentials(decryptedString);
            }
            attemptLogin(username, password);

        } catch (UnsupportedEncodingException e) {
            Log.e(TAG, "onFingerprintAuthenticated: failed to parse decrypted credentials", e);
            onFingerprintError("Failed to parse decrypted credentials");
        }
    }

    @Override
    public void onFingerprintError(@Nullable CharSequence errorMessage) {
        //TODO pass in the TYPE of error here. Allow user to customize message they want to display based on type of error
        //TODO reload view without surelock dialog - fall back on password login
        Toast.makeText(this, errorMessage, Toast.LENGTH_LONG).show();
    }

    private byte[] getFormattedCredentialsForEncryption(@NonNull String username, @NonNull String password)
            throws UnsupportedEncodingException {
        final String creds = String.format("%s]%s", username, password); //TODO move delimiter to constant
        return creds.getBytes("UTF-8");
    }

    private String getUsernameFromFormattedCredentials(String formattedCredentials) {
        String[] credentials = formattedCredentials.split("]");
        return credentials[0];
    }

    private String getPasswordFromFormattedCredentials(String formattedCredentials) {
        String[] credentials = formattedCredentials.split("]");
        return credentials[1];
    }
}