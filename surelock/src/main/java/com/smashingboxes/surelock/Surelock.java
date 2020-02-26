package com.smashingboxes.surelock;

import android.annotation.TargetApi;
import android.app.KeyguardManager;
import android.content.Context;
import android.content.Intent;
import android.content.res.TypedArray;
import android.os.Build;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyPermanentlyInvalidatedException;
import android.security.keystore.KeyProperties;
import androidx.annotation.IntDef;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.annotation.StyleRes;
import androidx.biometric.BiometricManager;
import androidx.biometric.BiometricPrompt;
import androidx.core.content.ContextCompat;
import androidx.fragment.app.FragmentActivity;

import android.text.TextUtils;
import android.util.Log;
import android.widget.Toast;

import java.io.IOException;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.concurrent.Executor;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

/**
 * Created by Tyler McCraw on 2/17/17.
 * <p>
 *     Singleton class which manages authentication
 *     via the FingerprintManager APIs and handles
 *     encryption & decryption on its own.
 *
 *     Call initialize() before any other functions so
 *     that Surelock can prepare for fingerprint authentication
 *
 *     Call store() to store credentials on the user's device.
 *     This will handle encryption and set some things up
 *     for decryption later on.
 *
 *     Call loginWithFingerprint() once Surelock has stored
 *     the credentials. Surelock will handle all decryption for you.
 *     Elementary, my dear Watson!
 * </p>
 */

@TargetApi(Build.VERSION_CODES.M)
public class Surelock {

    private static final String KEY_INIT_IALIZ_ATION_VEC_TOR = "com.smashingboxes.surelock.KEY_INIT_IALIZ_ATION_VEC_TOR";
    private static final String TAG = Surelock.class.getSimpleName();

    @Retention(RetentionPolicy.SOURCE)
    @IntDef({SYMMETRIC, ASYMMETRIC})
    public @interface EncryptionType {}
    public static final int SYMMETRIC = 0;
    public static final int ASYMMETRIC = 1;
    private int encryptionType = SYMMETRIC; //TODO consider allowing developers to change this if they want


    private SurelockFingerprintListener listener;
    private BiometricPrompt biometricPrompt;
    private BiometricPrompt.PromptInfo promptInfo;
    private int mCipherOperationMode;
    private byte[] mEncryptValue;
    private String mDecryptKey;
    private KeyStore keyStore;
    private KeyGenerator keyGenerator;
    private KeyPairGenerator keyPairGenerator;
    private KeyFactory keyFactory;

    //Set from Builder
    private SurelockStorage storage;
    private final String keyStoreAlias;

    public static Surelock initialize(@NonNull Builder builder) {
        return new Surelock(builder);
    }

    Surelock(Builder builder) {
        if (builder.fragmentActivity instanceof SurelockFingerprintListener) {
            this.listener = (SurelockFingerprintListener) builder.fragmentActivity;
        } else {
            throw new RuntimeException(builder.fragmentActivity.toString()
                    + " must implement FingerprintListener");
        }

        this.storage = builder.storage;
        this.keyStoreAlias = builder.keyStoreAlias;

        try {
            setUpKeyStoreForEncryption();
        } catch (SurelockException e) {
            Log.e(TAG, "Failed to set up KeyStore", e);
        }

        Executor executor = ContextCompat.getMainExecutor(builder.fragmentActivity);
        biometricPrompt = new BiometricPrompt(builder.fragmentActivity, executor, biometricCallback);
        promptInfo = setupPromptInfo(builder.fragmentActivity, builder.styleId);
    }

    private BiometricPrompt.AuthenticationCallback biometricCallback = new BiometricPrompt.AuthenticationCallback() {
        @Override
        public void onAuthenticationError(int errorCode, @NonNull CharSequence errString) {
            super.onAuthenticationError(errorCode, errString);
            listener.onFingerprintError(errString);
        }

        @Override
        public void onAuthenticationSucceeded(@NonNull BiometricPrompt.AuthenticationResult result) {
            super.onAuthenticationSucceeded(result);
            if (Cipher.ENCRYPT_MODE == mCipherOperationMode) {
                try {
                    final byte[] encryptedValue = result.getCryptoObject().getCipher().doFinal(mEncryptValue);
                    storage.createOrUpdate(mDecryptKey, encryptedValue);
                    listener.onFingerprintEnrolled();
                } catch (IllegalBlockSizeException | BadPaddingException e) {
                    listener.onFingerprintError(e.getMessage());
                }
            } else if (Cipher.DECRYPT_MODE == mCipherOperationMode) {
                byte[] encryptedValue = storage.get(mDecryptKey);
                byte[] decryptedValue;
                try {
                    decryptedValue = result.getCryptoObject().getCipher().doFinal(encryptedValue);
                    listener.onFingerprintAuthenticated(decryptedValue);
                } catch (BadPaddingException | IllegalBlockSizeException e) {
                    listener.onFingerprintError(e.getMessage());
                }
            }
        }

        @Override
        public void onAuthenticationFailed() {
            super.onAuthenticationFailed();
            listener.onFingerprintError(null);
        }
    };

    private BiometricPrompt.PromptInfo setupPromptInfo(FragmentActivity fragmentActivity, @StyleRes int styleId) {
        BiometricPrompt.PromptInfo.Builder promptInfoBuilder = new BiometricPrompt.PromptInfo.Builder();
        TypedArray attrs = fragmentActivity.obtainStyledAttributes(styleId, R.styleable
                .BiometricDialog);
        String titleText = attrs.getString(R.styleable.BiometricDialog_biometric_title_text);
        if(!TextUtils.isEmpty(titleText)) {
            promptInfoBuilder.setTitle(titleText);
        } else {
            promptInfoBuilder.setTitle(fragmentActivity.getResources().getString(R.string.fingerprint_title));
        }
        String descriptionText = attrs.getString(R.styleable.BiometricDialog_biometric_description_text);
        if(!TextUtils.isEmpty(descriptionText)) {
            promptInfoBuilder.setDescription(descriptionText);
        } else {
            promptInfoBuilder.setDescription(fragmentActivity.getResources().getString(R.string.fingerprint_description));
        }
        String negativeButtonText = attrs.getString(R.styleable.BiometricDialog_biometric_negative_button_text);
        if(!TextUtils.isEmpty(negativeButtonText)) {
            promptInfoBuilder.setNegativeButtonText(negativeButtonText);
        }
        attrs.recycle();
        return promptInfoBuilder.build();
    }

    /**
     * Check if user's device has fingerprint hardware
     *
     * @return true if fingerprint hardware is detected
     */
    @SuppressWarnings({"MissingPermission"})
    public static boolean hasFingerprintHardware(Context context) {
        return BiometricManager.from(context).canAuthenticate() != BiometricManager.BIOMETRIC_ERROR_NO_HARDWARE;
    }

    /**
     * Check if fingerprints have been set up for the user's device
     *
     * @return true if fingerprints have been enrolled. Otherwise, false.
     */
    @SuppressWarnings({"MissingPermission"})
    public static boolean hasUserEnrolledFingerprints(Context context) {
        return BiometricManager.from(context).canAuthenticate() == BiometricManager.BIOMETRIC_SUCCESS;
    }

    /**
     * Check if user has set a Screen Lock via PIN, pattern or password for the device
     * or a SIM card is currently locked
     *
     * @return true if user has set one of these screen lock methods or if the SIM card is locked.
     */
    public static boolean hasUserEnabledSecureLock(Context context) {
        KeyguardManager keyguardManager = context.getSystemService(KeyguardManager.class);
        return keyguardManager.isKeyguardSecure();
    }

    /**
     * Check if user has all of the necessary setup to allow fingerprint authentication
     * to be used for this application
     *
     * @param showMessaging set to true if you want Surelock to handle messaging for you.
     *                      It is recommended to set this to true.
     * @return true if user has fingerprint hardware, has enabled secure lock, and has enrolled fingerprints
     */
    public static boolean fingerprintAuthIsSetUp(Context context, boolean showMessaging) {
        if (!hasFingerprintHardware(context)) {
            return false;
        }
        if (!hasUserEnabledSecureLock(context)) {
            if (showMessaging) {
                // Show a message telling the user they haven't set up a fingerprint or lock screen.
                Toast.makeText(context, context.getString(R.string.error_toast_user_enable_securelock), Toast.LENGTH_LONG).show();
                context.startActivity(new Intent(android.provider.Settings.ACTION_SECURITY_SETTINGS));
            }
            return false;
        }
        if (!hasUserEnrolledFingerprints(context)) {
            if (showMessaging) {
                // This happens when no fingerprints are registered.
                Toast.makeText(context, R.string.error_toast_user_enroll_fingerprints, Toast.LENGTH_LONG).show();
                context.startActivity(new Intent(android.provider.Settings.ACTION_SECURITY_SETTINGS));
            }
            return false;
        }
        return true;
    }

    /**
     * Encrypt a value and store it at the specified key
     *
     * @param key pointer in storage to encrypted value
     * @param value value to be encrypted and stored
     */
    public void store(String key, byte[] value) throws SurelockException {
        initKeyStoreKey();
        Cipher cipher;
        try {
            cipher = initCipher(Cipher.ENCRYPT_MODE);
        } catch (InvalidKeyException | UnrecoverableKeyException | KeyStoreException e) {
            throw new SurelockException("Failed to init Cipher for encryption", null);
        }
        try {
            final byte[] encryptedValue = cipher.doFinal(value);
            storage.createOrUpdate(key, encryptedValue);
        } catch (IllegalBlockSizeException | BadPaddingException e) {
            Log.e(TAG, "Encryption failed", e);
        }
    }

    /**
     * Enroll a fingerprint, encrypt a value, and store the value at the specified key
     *
     * @param key            he key where encrypted values are stored
     * @param valueToEncrypt The value to encrypt and store
     * @throws SurelockException
     */
    public void enrollFingerprintAndStore(@NonNull String key, @NonNull byte[] valueToEncrypt) throws SurelockException {
        initKeyStoreKey();
        Cipher cipher;
        try {
            try {
                cipher = initCipher(Cipher.ENCRYPT_MODE);
            } catch (InvalidKeyException | UnrecoverableKeyException | KeyStoreException e) {
                throw new SurelockException("Failed to init Cipher for encryption", e);
            }
        } catch (RuntimeException e) {
            listener.onFingerprintError(null); //TODO we need better management of all of these listeners passed everywhere.
            return;
        }

        if (cipher != null) {
            mCipherOperationMode = Cipher.ENCRYPT_MODE;
            mEncryptValue = valueToEncrypt;
            mDecryptKey = key;
            biometricPrompt.authenticate(promptInfo, new BiometricPrompt.CryptoObject(cipher));
        } else {
            throw new SurelockException("Failed to init Cipher for encryption", null);
        }
    }

    /**
     * Log in using fingerprint authentication
     *
     * @param key The key where encrypted values are stored
     * @throws SurelockInvalidKeyException If the cipher could not be initialized
     */
    public void loginWithFingerprint(@NonNull String key) throws SurelockInvalidKeyException {
        Cipher cipher;
        try {
            cipher = initCipher(Cipher.DECRYPT_MODE);
        } catch (InvalidKeyException | UnrecoverableKeyException | KeyStoreException e) {
            // Key may be invalid due to new fingerprint enrollment
            // Try taking the user back through a new enrollment
            throw new SurelockInvalidKeyException("Failed to init Cipher. Key may be invalidated. Try re-enrolling.", null);
        } catch (RuntimeException e) {
            listener.onFingerprintError(null); //TODO we need better management of all of these listeners passed everywhere.
            return;
        }

        if (cipher != null) {
            mCipherOperationMode = Cipher.DECRYPT_MODE;
            mDecryptKey = key;
            biometricPrompt.authenticate(promptInfo, new BiometricPrompt.CryptoObject(cipher));
        } else {
            throw new SurelockInvalidKeyException("Failed to init Cipher. Key may be invalidated. Try re-enrolling.", null);
        }
    }

    public void hidePrompt() {
        biometricPrompt.cancelAuthentication();
    }

    /**
     * Initialize our KeyStore w/ the default security provider
     * Initialize a KeyGenerator using either RSA for asymmetric or AES for symmetric
     */
    private void setUpKeyStoreForEncryption() throws SurelockException {
        // NOTE: "AndroidKeyStore" is only supported in APIs 18+,
        // but since the FingerprintManager APIs support 23+, this doesn't matter.
        // https://developer.android.com/reference/java/security/KeyStore.html
        final String keyStoreProvider = "AndroidKeyStore";
        try {
            keyStore = KeyStore.getInstance(keyStoreProvider);
            keyStore.load(null);
        } catch (KeyStoreException e) {
            throw new SurelockException("Failed to get an instance of KeyStore", e);
        } catch (IOException | NoSuchAlgorithmException | CertificateException e) {
            throw new SurelockException("Failed to load keystore", e);
        }
        try {
            if (encryptionType == ASYMMETRIC) {
                keyPairGenerator = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_RSA, keyStoreProvider);
                keyFactory = KeyFactory.getInstance("RSA");
            } else {
                keyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, keyStoreProvider);
            }
        } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
            throw new SurelockException("Failed to get an instance of KeyGenerator", e);
        }
    }

    private Cipher getCipherInstance() throws NoSuchAlgorithmException, NoSuchPaddingException {
        if (encryptionType == ASYMMETRIC) {
            return Cipher.getInstance(
                    KeyProperties.KEY_ALGORITHM_RSA + "/"
                            + KeyProperties.BLOCK_MODE_ECB + "/"
                            + KeyProperties.ENCRYPTION_PADDING_RSA_PKCS1);
        } else {
            return Cipher.getInstance(
                    KeyProperties.KEY_ALGORITHM_AES + "/"
                    + KeyProperties.BLOCK_MODE_CBC + "/"
                    + KeyProperties.ENCRYPTION_PADDING_PKCS7);
        }
    }

    /**
     * Creates a KeyStore key which can only be used after the user has
     * authenticated with their fingerprint.
     *
     * @param keyName                          the name of the key to be created
     * @param invalidatedByBiometricEnrollment if {@code false} is passed, the created key will not be invalidated
     *                                         even if a new fingerprint is enrolled. The default value is {@code true},
     *                                         so passing {@code true} doesn't change the behavior (the key will be
     *                                         invalidated if a new fingerprint is enrolled.).
     *                                         Note: this parameter is only valid if the app works on Android N developer preview.
     */
    private void generateKeyStoreKey(@NonNull String keyName,
                                     boolean invalidatedByBiometricEnrollment) throws SurelockException {
        try {
            if (encryptionType == ASYMMETRIC) {
                keyPairGenerator.initialize(
                        new KeyGenParameterSpec.Builder(keyStoreAlias,
                                KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                                .setBlockModes(KeyProperties.BLOCK_MODE_ECB)
                                .setUserAuthenticationRequired(true)
                                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_PKCS1)
                                .build());

                keyPairGenerator.generateKeyPair();
            } else {
                // Set the alias of the entry in Android KeyStore where the key will appear
                // and the constraints (purposes) in the constructor of the Builder
                KeyGenParameterSpec.Builder builder = new KeyGenParameterSpec.Builder(keyName,
                        KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                        .setBlockModes(KeyProperties.BLOCK_MODE_CBC)
//                    .setKeySize(256) //TODO figure out if this is proper key size
                        // Require the user to authenticate with a fingerprint to authorize every use of the key
                        .setUserAuthenticationRequired(true)
//                    .setUserAuthenticationValidityDurationSeconds(AUTHENTICATION_DURATION_SECONDS)
                        .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_PKCS7);

                // This is a workaround to avoid crashes on devices whose API level is < 24
                // because KeyGenParameterSpec.Builder#setInvalidatedByBiometricEnrollment is only visible on API level +24.
                // Ideally there should be a compat library for KeyGenParameterSpec.Builder but
                // which isn't available yet.
//            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
//                builder.setInvalidatedByBiometricEnrollment(invalidatedByBiometricEnrollment);
//            }
                keyGenerator.init(builder.build());
                keyGenerator.generateKey();
            }
        } catch (InvalidAlgorithmParameterException | NullPointerException e) {
            throw new SurelockException("Failed to generate a key", e);
        }
    }

    private PublicKey getPublicKey() throws KeyStoreException, InvalidKeySpecException {
        PublicKey publicKey = keyStore.getCertificate(keyStoreAlias).getPublicKey();
        KeySpec spec = new X509EncodedKeySpec(publicKey.getEncoded());
        return keyFactory.generatePublic(spec);
    }

    private PrivateKey getPrivateKey() throws NoSuchAlgorithmException, UnrecoverableKeyException, KeyStoreException {
        return (PrivateKey) keyStore.getKey(keyStoreAlias, null);
    }

    /**
     * Initialize a Key for our KeyStore.
     * NOTE: It won't recreate one if a valid key already exists.
     */
    private void initKeyStoreKey() {
        try {
            SecretKey secretKey = (SecretKey) keyStore.getKey(keyStoreAlias, null);
            // Check to see if we need to create a new KeyStore key
            if (secretKey != null) {
                try {
                    if (encryptionType == ASYMMETRIC) {
                        getCipherInstance().init(Cipher.DECRYPT_MODE, secretKey);
                        return;
                    } else {
                        byte[] encryptionIv = getEncryptionIv();
                        if (encryptionIv != null) {
                            getCipherInstance().init(Cipher.DECRYPT_MODE, secretKey, new IvParameterSpec(encryptionIv));
                            return;
                        }
                    }
                } catch (KeyPermanentlyInvalidatedException e) {
                    Log.d(TAG, "Keys were invalidated. Creating new key...");
                }
            }

            storage.clearAll();

            //Create a new key
            generateKeyStoreKey(keyStoreAlias, true);
        } catch (GeneralSecurityException e) {
            throw new SurelockException("Surelock: Failed to prepare KeyStore for encryption", e);
        } catch (NoClassDefFoundError e) {
            throw new SurelockException("Surelock: API 23 or higher required.", e);
        }
    }

    /**
     * Initialize a Cipher for encryption
     *
     * @param opmode the operation mode of this cipher (this is one of
     * the following:
     * <code>ENCRYPT_MODE</code>, <code>DECRYPT_MODE</code>)
     * @return Cipher object to be used for encryption
     */
    private Cipher initCipher(int opmode) throws InvalidKeyException, UnrecoverableKeyException, KeyStoreException {
        Cipher cipher;
        try {
            cipher = getCipherInstance();
            if (encryptionType == ASYMMETRIC) {
                cipher.init(opmode, opmode == Cipher.ENCRYPT_MODE ? getPublicKey() : getPrivateKey());
            } else {
                SecretKey secretKey = (SecretKey) keyStore.getKey(keyStoreAlias, null);
                if (opmode == Cipher.ENCRYPT_MODE) {
                    cipher.init(opmode, secretKey);
                    setEncryptionIv(cipher.getIV());
                } else {
                    cipher.init(opmode, secretKey, new IvParameterSpec(getEncryptionIv()));
                }
            }
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidAlgorithmParameterException | InvalidKeySpecException e) {
            throw new SurelockException("Surelock: Failed to prepare Cipher for encryption", e);
        }
        return cipher;
    }

    private void setEncryptionIv(byte[] encryptionIv) {
        storage.createOrUpdate(KEY_INIT_IALIZ_ATION_VEC_TOR, encryptionIv);
    }

    /**
     * Get the Initialization Vector to be used for encryption/decryption
     * The IV needs to be persisted if used for encryption, since it will be required for decryption
     * @return initialization vector as byte array
     */
    @Nullable
    private byte[] getEncryptionIv() {
        return storage.get(KEY_INIT_IALIZ_ATION_VEC_TOR);
    }

    public static class Builder {

        private FragmentActivity fragmentActivity;
        @StyleRes
        private int styleId;
        private String keyStoreAlias;
        private SurelockStorage storage;

        public Builder(@NonNull FragmentActivity fragmentActivity) {
            this.fragmentActivity = fragmentActivity;
        }

        /**
         * Allows styling of the biometric prompt
         *
         * @param styleId The style resource file to be used for styling the dialog
         * @return This Builder to allow for method chaining
         */
        public Builder withStyle(@StyleRes int styleId) {
            this.styleId = styleId;
            return this;
        }

        /**
         * Indicates the alias to use for the keystore when using fingerprint login. This method
         * MUST be called before enrolling and logging in.
         *
         * @param keyStoreAlias The keystore alias to use
         * @return This Builder to allow for method chaining
         */
        public Builder withKeystoreAlias(@NonNull String keyStoreAlias) {
            this.keyStoreAlias = keyStoreAlias;
            return this;
        }

        /**
         * Indicates the SurelockStorage instance to use with fingerprint login. This method MUST
         * be called before enrolling and logging in.
         *
         * @param storage The SurelockStorage instance to use
         * @return This Builder to allow for method chaining
         */
        public Builder withSurelockStorage(@NonNull SurelockStorage storage) {
            this.storage = storage;
            return this;
        }

        /**
         * Creates the Surelock instance
         */
        public Surelock build() {
            checkFields();
            return Surelock.initialize(this);
        }

        private void checkFields() {
            if (TextUtils.isEmpty(keyStoreAlias)) {
                throw new IllegalStateException("The keystore alias cannot be empty.");
            }
            if (storage == null) {
                throw new IllegalStateException("SurelockStorage cannot be null.");
            }
        }

    }

}
