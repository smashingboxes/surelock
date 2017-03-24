package com.smashingboxes.surelock;

import android.annotation.TargetApi;
import android.app.FragmentManager;
import android.app.KeyguardManager;
import android.content.Context;
import android.content.Intent;
import android.hardware.fingerprint.FingerprintManager;
import android.os.Build;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyPermanentlyInvalidatedException;
import android.security.keystore.KeyProperties;
import android.support.annotation.IntDef;
import android.support.annotation.NonNull;
import android.support.annotation.Nullable;
import android.support.annotation.RequiresApi;
import android.support.annotation.StyleRes;
import android.util.Log;
import android.widget.Toast;

import java.io.IOException;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyFactory;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.spec.KeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
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
    private SurelockStorage storage;
    private FingerprintManager fingerprintManager;
    private KeyStore keyStore;
    private KeyGenerator keyGenerator;
    private KeyPairGenerator keyPairGenerator;
    private KeyFactory keyFactory;
    private final String keyStoreAlias;

    /**
     * Initializes the Surelock main class
     *
     * @return A new Surelock instance, or null if the device does not support fingerprint auth
     */
    @RequiresApi(api = Build.VERSION_CODES.M)
    public static Surelock initialize(Context context, SurelockStorage storage, String keystoreAlias) {
        return new Surelock(context, storage, keystoreAlias);
    }

    //TODO: We might want to make this private to enforce API version on initialize()
    public Surelock(Context context, SurelockStorage storage, String keystoreAlias) {
        if (context instanceof SurelockFingerprintListener) {
            this.listener = (SurelockFingerprintListener) context;
        } else {
            throw new RuntimeException(context.toString()
                    + " must implement FingerprintListener");
        }
        this.storage = storage;
        this.keyStoreAlias = keystoreAlias;
        try {
            setUpKeyStoreForEncryption();
        } catch (SurelockException e) {
            Log.e(TAG, "Failed to set up KeyStore", e);
        }

        fingerprintManager = context.getSystemService(FingerprintManager.class);
    }

    /**
     * Check if user's device has fingerprint hardware
     *
     * @return true if fingerprint hardware is detected
     */
    @SuppressWarnings({"MissingPermission"})
    @RequiresApi(api = Build.VERSION_CODES.M)
    public static boolean hasFingerprintHardware(Context context) {
        return context.getSystemService(FingerprintManager.class).isHardwareDetected();
    }

    /**
     * Check if fingerprints have been set up for the user's device
     *
     * @return true if fingerprints have been enrolled. Otherwise, false.
     */
    @SuppressWarnings({"MissingPermission"})
    @RequiresApi(api = Build.VERSION_CODES.M)
    public static boolean hasUserEnrolledFingerprints(Context context) {
        return context.getSystemService(FingerprintManager.class).hasEnrolledFingerprints();
    }

    /**
     * Check if user has set a Screen Lock via PIN, pattern or password for the device
     * or a SIM card is currently locked
     *
     * @return true if user has set one of these screen lock methods or if the SIM card is locked.
     */
    @RequiresApi(api = Build.VERSION_CODES.M)
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
    @RequiresApi(api = Build.VERSION_CODES.M)
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
    public void store(String key, byte[] value) {
        initKeyStoreKey();
        Cipher cipher = initCipher(Cipher.ENCRYPT_MODE);
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
     * @param key pointer in storage to encrypted value
     * @param valueToEncrypt value to be encrypted and stored
     * @param fragmentManager FragmentManger used to load the dialog fragment
     * @param fingerprintDialogFragmentTag tag associated with the dialog fragment
     * @param styleId resource id of the style set for custom dialog attributes
     */
    public void enrollFingerprintAndStore(String key, byte[] valueToEncrypt,
                                          @NonNull FragmentManager fragmentManager,
                                          String fingerprintDialogFragmentTag,
                                          @StyleRes int styleId) {
        SurelockDefaultDialog fragment = (SurelockDefaultDialog) fragmentManager.findFragmentByTag(fingerprintDialogFragmentTag);
        if (fragment == null) {
            fragment = SurelockDefaultDialog.newInstance(Cipher.ENCRYPT_MODE, valueToEncrypt, styleId);
        }
        enrollFingerprintAndStore(key, fragment, fragmentManager, fingerprintDialogFragmentTag);
    }

    /**
     * Enroll a fingerprint, encrypt a value, and store the value at the specified key
     * Use this if you want to use your own custom dialog rather than Surelock's default dialog
     *
     * @param key pointer in storage to encrypted value
     * @param surelockFragment your own custom Surelock Fragment
     * @param fragmentManager FragmentManger used to load the dialog fragment
     * @param fingerprintDialogFragmentTag tag associated with the dialog fragment
     */
    public void enrollFingerprintAndStore(String key,
                                          SurelockFragment surelockFragment,
                                          @NonNull FragmentManager fragmentManager,
                                          String fingerprintDialogFragmentTag) {
        initKeyStoreKey();
        Cipher cipher;
        try {
            cipher = initCipher(Cipher.ENCRYPT_MODE);
        } catch (RuntimeException e) {
            listener.onFingerprintError(null); //TODO we need better management of all of these listeners passed everywhere.
            return;
        }

        if (cipher != null) {
            showFingerprintDialog(key, cipher, surelockFragment, fragmentManager, fingerprintDialogFragmentTag);
        } else {
            // TODO
            // This happens if the lock screen has been disabled or a fingerprint got
            // enrolled. Thus show the dialog to authenticate with their password first
            // and ask the user if they want to authenticate with fingerprints in the
            // future
//            showFingerprintDialog(cipher, NEW_FINGERPRINT_ENROLLED, surelockFragment, fragmentManager, fingerprintDialogFragmentTag);
        }
    }

    /**
     * Login with the default Surelock dialog fragment
     *
     * @param key                          pointer in storage to encrypted value
     * @param fragmentManager              FragmentManger used to load the dialog fragment
     * @param fingerprintDialogFragmentTag tag associated with the dialog fragment
     * @param styleId                      resource id of the style set for custom dialog attributes
     */
    public void loginWithFingerprint(@NonNull String key,
                                     @NonNull FragmentManager fragmentManager,
                                     String fingerprintDialogFragmentTag,
                                     @StyleRes int styleId) {
        SurelockDefaultDialog fragment = (SurelockDefaultDialog) fragmentManager.findFragmentByTag(fingerprintDialogFragmentTag);
        if (fragment == null) {
            fragment = SurelockDefaultDialog.newInstance(Cipher.DECRYPT_MODE, styleId);
        }
        loginWithFingerprint(key, fragment, fragmentManager, fingerprintDialogFragmentTag);
    }

    /**
     * Login with a custom dialog fragment
     *
     * @param key pointer in storage to encrypted value
     * @param surelockFragment your own custom Surelock Fragment
     * @param fragmentManager FragmentManger used to load the dialog fragment
     * @param fingerprintDialogFragmentTag tag associated with the dialog fragment
     */
    public void loginWithFingerprint(@NonNull String key,
                                     SurelockFragment surelockFragment,
                                     @NonNull FragmentManager fragmentManager,
                                     String fingerprintDialogFragmentTag) {
        Cipher cipher;
        try {
            cipher = initCipher(Cipher.DECRYPT_MODE);
        } catch (RuntimeException e) {
            listener.onFingerprintError(null); //TODO we need better management of all of these listeners passed everywhere.
            return;
        }

        if (cipher != null) {
            showFingerprintDialog(key, cipher, surelockFragment, fragmentManager, fingerprintDialogFragmentTag);
        } else {
            // TODO
            // This happens if the lock screen has been disabled or a fingerprint got
            // enrolled. Thus show the dialog to authenticate with their password first
            // and ask the user if they want to authenticate with fingerprints in the
            // future
//            showFingerprintDialog(cipher, NEW_FINGERPRINT_ENROLLED, surelockFragment, fragmentManager, fingerprintDialogFragmentTag);
        }
    }

    private void showFingerprintDialog(@NonNull String key,
                                       @NonNull Cipher cipher,
                                       SurelockFragment surelockFragment,
                                       @NonNull FragmentManager fragmentManager, String fingerprintDialogFragmentTag) {
        surelockFragment.init(fingerprintManager, new FingerprintManager.CryptoObject(cipher), key, storage);
        surelockFragment.show(fragmentManager, fingerprintDialogFragmentTag);
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

    private Cipher getCipherInstance() throws GeneralSecurityException {
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

    private PublicKey getPublicKey() throws GeneralSecurityException {
        PublicKey publicKey = keyStore.getCertificate(keyStoreAlias).getPublicKey();
        KeySpec spec = new X509EncodedKeySpec(publicKey.getEncoded());
        return keyFactory.generatePublic(spec);
    }

    private PrivateKey getPrivateKey() throws GeneralSecurityException {
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
                    } else {
                        byte[] encryptionIv = getEncryptionIv();
                        if (encryptionIv != null) {
                            getCipherInstance().init(Cipher.DECRYPT_MODE, secretKey, new IvParameterSpec(encryptionIv));
                        }
                    }
                    return;
                } catch (KeyPermanentlyInvalidatedException e) {
                    Log.d(TAG, "Keys were invalidated. Creating new key...");
                }
            }

            storage.clearAll();

            //Create a new key
            generateKeyStoreKey(keyStoreAlias, true);
        } catch (GeneralSecurityException e) {
            throw new SurelockException("Surelock: Failed to prepare KeyStore for encryption", e);
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
    private Cipher initCipher(int opmode) {
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
        } catch (GeneralSecurityException e) {
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

}
