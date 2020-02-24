package com.smashingboxes.surelock

import android.annotation.TargetApi
import android.app.FragmentManager
import android.app.KeyguardManager
import android.content.Context
import android.content.Intent
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.KeyProperties
import android.support.annotation.IntDef
import android.support.annotation.StyleRes
import android.support.v4.hardware.fingerprint.FingerprintManagerCompat
import android.util.Log
import android.widget.Toast

import java.io.IOException
import java.security.GeneralSecurityException
import java.security.InvalidAlgorithmParameterException
import java.security.InvalidKeyException
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.KeyStoreException
import java.security.NoSuchAlgorithmException
import java.security.NoSuchProviderException
import java.security.PrivateKey
import java.security.PublicKey
import java.security.UnrecoverableKeyException
import java.security.cert.CertificateException
import java.security.spec.InvalidKeySpecException
import java.security.spec.X509EncodedKeySpec

import javax.crypto.BadPaddingException
import javax.crypto.Cipher
import javax.crypto.IllegalBlockSizeException
import javax.crypto.KeyGenerator
import javax.crypto.NoSuchPaddingException
import javax.crypto.SecretKey
import javax.crypto.spec.IvParameterSpec

/**
 * Created by Tyler McCraw on 2/17/17.
 *
 *
 * Singleton class which manages authentication
 * via the FingerprintManager APIs and handles
 * encryption & decryption on its own.
 *
 * Call initialize() before any other functions so
 * that Surelock can prepare for fingerprint authentication
 *
 * Call store() to store credentials on the user's device.
 * This will handle encryption and set some things up
 * for decryption later on.
 *
 * Call loginWithFingerprint() once Surelock has stored
 * the credentials. Surelock will handle all decryption for you.
 * Elementary, my dear Watson!
 *
 */

@TargetApi(Build.VERSION_CODES.M)
class Surelock internal constructor(builder: Builder) {
    private val encryptionType = SYMMETRIC //TODO consider allowing developers to change this if they want


    private var listener: SurelockFingerprintListener? = null
    private val fingerprintManager: FingerprintManagerCompat
    private lateinit var keyStore: KeyStore
    private var keyGenerator: KeyGenerator? = null
    private var keyPairGenerator: KeyPairGenerator? = null
    private lateinit var keyFactory: KeyFactory

    //Set from Builder
    private val storage: SurelockStorage?
    private val keyStoreAlias: String?
    private val surelockFragmentTag: String?
    private val surelockFragment: SurelockFragment?
    private val fragmentManager: FragmentManager?
    private val useDefault: Boolean
    @StyleRes
    private val styleId: Int

    private val cipherInstance: Cipher
        @Throws(NoSuchAlgorithmException::class, NoSuchPaddingException::class)
        get() = if (encryptionType == ASYMMETRIC) {
            Cipher.getInstance(
                KeyProperties.KEY_ALGORITHM_RSA + "/"
                    + KeyProperties.BLOCK_MODE_ECB + "/"
                    + KeyProperties.ENCRYPTION_PADDING_RSA_PKCS1)
        } else {
            Cipher.getInstance(
                KeyProperties.KEY_ALGORITHM_AES + "/"
                    + KeyProperties.BLOCK_MODE_CBC + "/"
                    + KeyProperties.ENCRYPTION_PADDING_PKCS7)
        }

    private val publicKey: PublicKey
        @Throws(KeyStoreException::class, InvalidKeySpecException::class)
        get() {
            val publicKey = keyStore.getCertificate(keyStoreAlias).publicKey
            val spec = X509EncodedKeySpec(publicKey.encoded)
            return keyFactory.generatePublic(spec)
        }

    private val privateKey: PrivateKey
        @Throws(NoSuchAlgorithmException::class, UnrecoverableKeyException::class,
            KeyStoreException::class)
        get() = keyStore.getKey(keyStoreAlias, null) as PrivateKey

    /**
     * Get the Initialization Vector to be used for encryption/decryption
     * The IV needs to be persisted if used for encryption, since it will be required for decryption
     * @return initialization vector as byte array
     */
    private var encryptionIv: ByteArray?
        get() = storage?.get(KEY_INIT_IALIZ_ATION_VEC_TOR)
        set(encryptionIv) = storage!!.createOrUpdate(KEY_INIT_IALIZ_ATION_VEC_TOR, encryptionIv ?: ByteArray(0))

    @Retention(AnnotationRetention.SOURCE)
    @IntDef(SYMMETRIC, ASYMMETRIC)
    annotation class EncryptionType

    init {
        if (builder.context is SurelockFingerprintListener) {
            this.listener = builder.context
        } else {
            throw RuntimeException(
                builder.context.toString() + " must implement FingerprintListener")
        }

        this.storage = builder.storage
        this.keyStoreAlias = builder.keyStoreAlias
        this.surelockFragmentTag = builder.surelockFragmentTag
        this.surelockFragment = builder.surelockFragment
        this.fragmentManager = builder.fragmentManager
        this.useDefault = builder.useDefault
        this.styleId = builder.styleId

        try {
            setUpKeyStoreForEncryption()
        } catch (e: SurelockException) {
            Log.e(TAG, "Failed to set up KeyStore", e)
        }

        fingerprintManager = FingerprintManagerCompat.from(builder.context)
    }

    /**
     * Encrypt a value and store it at the specified key
     *
     * @param key pointer in storage to encrypted value
     * @param value value to be encrypted and stored
     */
    @Throws(SurelockException::class)
    fun store(key: String, value: ByteArray) {
        initKeyStoreKey()
        val cipher: Cipher
        try {
            cipher = initCipher(Cipher.ENCRYPT_MODE)
        } catch (e: InvalidKeyException) {
            throw SurelockException("Failed to init Cipher for encryption", null)
        } catch (e: UnrecoverableKeyException) {
            throw SurelockException("Failed to init Cipher for encryption", null)
        } catch (e: KeyStoreException) {
            throw SurelockException("Failed to init Cipher for encryption", null)
        }

        try {
            val encryptedValue = cipher.doFinal(value)
            storage?.createOrUpdate(key, encryptedValue)
        } catch (e: IllegalBlockSizeException) {
            Log.e(TAG, "Encryption failed", e)
        } catch (e: BadPaddingException) {
            Log.e(TAG, "Encryption failed", e)
        }

    }

    /**
     * Enroll a fingerprint, encrypt a value, and store the value at the specified key
     *
     * @param key            he key where encrypted values are stored
     * @param valueToEncrypt The value to encrypt and store
     * @throws SurelockException
     */
    @Throws(SurelockException::class)
    fun enrollFingerprintAndStore(key: String, valueToEncrypt: ByteArray) {
        initKeyStoreKey()
        val cipher: Cipher?
        try {
            try {
                cipher = initCipher(Cipher.ENCRYPT_MODE)
            } catch (e: InvalidKeyException) {
                throw SurelockException("Failed to init Cipher for encryption", e)
            } catch (e: UnrecoverableKeyException) {
                throw SurelockException("Failed to init Cipher for encryption", e)
            } catch (e: KeyStoreException) {
                throw SurelockException("Failed to init Cipher for encryption", e)
            }

        } catch (e: RuntimeException) {
            listener?.onFingerprintError(
                null) //TODO we need better management of all of these listeners passed everywhere.
            return
        }

        if (cipher != null) {
            showFingerprintDialog(key, cipher, getSurelockFragment(true), valueToEncrypt)
        } else {
            throw SurelockException("Failed to init Cipher for encryption", null)
        }
    }

    /**
     * Log in using fingerprint authentication
     *
     * @param key The key where encrypted values are stored
     * @throws SurelockInvalidKeyException If the cipher could not be initialized
     */
    @Throws(SurelockInvalidKeyException::class)
    fun loginWithFingerprint(key: String) {
        val cipher: Cipher?
        try {
            cipher = initCipher(Cipher.DECRYPT_MODE)
        } catch (e: InvalidKeyException) {
            // Key may be invalid due to new fingerprint enrollment
            // Try taking the user back through a new enrollment
            throw SurelockInvalidKeyException(
                "Failed to init Cipher. Key may be invalidated. Try re-enrolling.", null)
        } catch (e: UnrecoverableKeyException) {
            throw SurelockInvalidKeyException(
                "Failed to init Cipher. Key may be invalidated. Try re-enrolling.", null)
        } catch (e: KeyStoreException) {
            throw SurelockInvalidKeyException(
                "Failed to init Cipher. Key may be invalidated. Try re-enrolling.", null)
        } catch (e: RuntimeException) {
            listener?.onFingerprintError(
                null) //TODO we need better management of all of these listeners passed everywhere.
            return
        }

        if (cipher != null) {
            showFingerprintDialog(key, cipher, getSurelockFragment(false), null)
        } else {
            throw SurelockInvalidKeyException(
                "Failed to init Cipher. Key may be invalidated. Try re-enrolling.", null)
        }
    }

    private fun getSurelockFragment(isEnrolling: Boolean): SurelockFragment {
        if (surelockFragment != null) {
            return surelockFragment
        }
        return if (useDefault) {
            SurelockDefaultDialog.newInstance(if (isEnrolling)
                Cipher.ENCRYPT_MODE
            else
                Cipher.DECRYPT_MODE, styleId)
        } else {
            SurelockMaterialDialog.newInstance(if (isEnrolling)
                Cipher.ENCRYPT_MODE
            else
                Cipher.DECRYPT_MODE)
        }
    }

    private fun showFingerprintDialog(key: String, cipher: Cipher,
                                      surelockFragment: SurelockFragment,
                                      valueToEncrypt: ByteArray?) {
        surelockFragment.init(fingerprintManager, FingerprintManagerCompat.CryptoObject(cipher),
            key, storage!!, valueToEncrypt)
        surelockFragment.show(fragmentManager!!, surelockFragmentTag!!)
    }

    /**
     * Initialize our KeyStore w/ the default security provider
     * Initialize a KeyGenerator using either RSA for asymmetric or AES for symmetric
     */
    @Throws(SurelockException::class)
    private fun setUpKeyStoreForEncryption() {
        // NOTE: "AndroidKeyStore" is only supported in APIs 18+,
        // but since the FingerprintManager APIs support 23+, this doesn't matter.
        // https://developer.android.com/reference/java/security/KeyStore.html
        val keyStoreProvider = "AndroidKeyStore"
        try {
            keyStore = KeyStore.getInstance(keyStoreProvider)
            keyStore?.load(null)
        } catch (e: KeyStoreException) {
            throw SurelockException("Failed to get an instance of KeyStore", e)
        } catch (e: IOException) {
            throw SurelockException("Failed to load keystore", e)
        } catch (e: NoSuchAlgorithmException) {
            throw SurelockException("Failed to load keystore", e)
        } catch (e: CertificateException) {
            throw SurelockException("Failed to load keystore", e)
        }

        try {
            if (encryptionType == ASYMMETRIC) {
                keyPairGenerator = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_RSA,
                    keyStoreProvider)
                keyFactory = KeyFactory.getInstance("RSA")
            } else {
                keyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES,
                    keyStoreProvider)
            }
        } catch (e: NoSuchAlgorithmException) {
            throw SurelockException("Failed to get an instance of KeyGenerator", e)
        } catch (e: NoSuchProviderException) {
            throw SurelockException("Failed to get an instance of KeyGenerator", e)
        }

    }

    /**
     * Creates a KeyStore key which can only be used after the user has
     * authenticated with their fingerprint.
     *
     * @param keyName                          the name of the key to be created
     * @param invalidatedByBiometricEnrollment if `false` is passed, the created key will not be invalidated
     * even if a new fingerprint is enrolled. The default value is `true`,
     * so passing `true` doesn't change the behavior (the key will be
     * invalidated if a new fingerprint is enrolled.).
     * Note: this parameter is only valid if the app works on Android N developer preview.
     */
    @Throws(SurelockException::class)
    private fun generateKeyStoreKey(keyName: String,
                                    invalidatedByBiometricEnrollment: Boolean) {
        try {
            if (encryptionType == ASYMMETRIC) {
                keyPairGenerator?.initialize(
                    KeyGenParameterSpec.Builder(keyStoreAlias!!,
                        KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                        .setBlockModes(KeyProperties.BLOCK_MODE_ECB)
                        .setUserAuthenticationRequired(true)
                        .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_PKCS1)
                        .build())

                keyPairGenerator?.generateKeyPair()
            } else {
                // Set the alias of the entry in Android KeyStore where the key will appear
                // and the constraints (purposes) in the constructor of the Builder
                val builder = KeyGenParameterSpec.Builder(keyName,
                    KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                    .setBlockModes(KeyProperties.BLOCK_MODE_CBC)
                    //                    .setKeySize(256) //TODO figure out if this is proper key size
                    // Require the user to authenticate with a fingerprint to authorize every use of the key
                    .setUserAuthenticationRequired(true)
                    //                    .setUserAuthenticationValidityDurationSeconds(AUTHENTICATION_DURATION_SECONDS)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_PKCS7)

                // This is a workaround to avoid crashes on devices whose API level is < 24
                // because KeyGenParameterSpec.Builder#setInvalidatedByBiometricEnrollment is only visible on API level +24.
                // Ideally there should be a compat library for KeyGenParameterSpec.Builder but
                // which isn't available yet.
                //            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
                //                builder.setInvalidatedByBiometricEnrollment(invalidatedByBiometricEnrollment);
                //            }
                keyGenerator?.init(builder.build())
                keyGenerator?.generateKey()
            }
        } catch (e: InvalidAlgorithmParameterException) {
            throw SurelockException("Failed to generate a key", e)
        } catch (e: NullPointerException) {
            throw SurelockException("Failed to generate a key", e)
        }

    }

    /**
     * Initialize a Key for our KeyStore.
     * NOTE: It won't recreate one if a valid key already exists.
     */
    private fun initKeyStoreKey() {
        try {
            val secretKey = keyStore.getKey(keyStoreAlias, null) as SecretKey?
            // Check to see if we need to create a new KeyStore key
            if (secretKey != null) {
                try {
                    if (encryptionType == ASYMMETRIC) {
                        cipherInstance.init(Cipher.DECRYPT_MODE, secretKey)
                        return
                    } else {
                        val encryptionIv = encryptionIv
                        if (encryptionIv != null) {
                            cipherInstance.init(Cipher.DECRYPT_MODE, secretKey,
                                IvParameterSpec(encryptionIv))
                            return
                        }
                    }
                } catch (e: KeyPermanentlyInvalidatedException) {
                    Log.d(TAG, "Keys were invalidated. Creating new key...")
                }

            }

            storage?.clearAll()

            //Create a new key
            generateKeyStoreKey(keyStoreAlias!!, true)
        } catch (e: GeneralSecurityException) {
            throw SurelockException("Surelock: Failed to prepare KeyStore for encryption", e)
        } catch (e: NoClassDefFoundError) {
            throw SurelockException("Surelock: API 23 or higher required.", e)
        }

    }

    /**
     * Initialize a Cipher for encryption
     *
     * @param opmode the operation mode of this cipher (this is one of
     * the following:
     * `ENCRYPT_MODE`, `DECRYPT_MODE`)
     * @return Cipher object to be used for encryption
     */
    @Throws(InvalidKeyException::class, UnrecoverableKeyException::class, KeyStoreException::class)
    private fun initCipher(opmode: Int): Cipher {
        val cipher: Cipher
        try {
            cipher = cipherInstance
            if (encryptionType == ASYMMETRIC) {
                cipher.init(opmode, if (opmode == Cipher.ENCRYPT_MODE) publicKey else privateKey)
            } else {
                val secretKey = keyStore.getKey(keyStoreAlias, null) as SecretKey?
                if (opmode == Cipher.ENCRYPT_MODE) {
                    cipher.init(opmode, secretKey)
                    encryptionIv = cipher.iv
                } else {
                    cipher.init(opmode, secretKey, IvParameterSpec(encryptionIv))
                }
            }
        } catch (e: NoSuchAlgorithmException) {
            throw SurelockException("Surelock: Failed to prepare Cipher for encryption", e)
        } catch (e: NoSuchPaddingException) {
            throw SurelockException("Surelock: Failed to prepare Cipher for encryption", e)
        } catch (e: InvalidAlgorithmParameterException) {
            throw SurelockException("Surelock: Failed to prepare Cipher for encryption", e)
        } catch (e: InvalidKeySpecException) {
            throw SurelockException("Surelock: Failed to prepare Cipher for encryption", e)
        }

        return cipher
    }

    class Builder(val context: Context) {
        var fragmentManager: FragmentManager? = null
        var surelockFragmentTag: String? = null
        var surelockFragment: SurelockFragment? = null
        var useDefault: Boolean = false
        @StyleRes
        var styleId: Int = 0
        var keyStoreAlias: String? = null
        var storage: SurelockStorage? = null

        /**
         * Indicates that fingerprint login should be prompted using the SurelockDefaultDialog
         * class. This is a fullscreen dialog that can be styled to match an app's theme.
         *
         * @param styleId The style resource file to be used for styling the dialog
         * @return This Builder to allow for method chaining
         */
        fun withDefaultDialog(@StyleRes styleId: Int): Builder {
            useDefault = true
            surelockFragment = null
            this.styleId = styleId
            return this
        }

        /**
         * Indicates that fingerprint login should be prompted using the SurelockMaterialDialog.
         * This dialog follows Material Design guidelines.
         *
         * @return This Builder to allow for method chaining
         */
        fun withMaterialDialog(): Builder {
            useDefault = false
            surelockFragment = null
            return this
        }

        /**
         * Indicates that fingerprint login should be prompted using the given dialog.
         *
         * @param surelockFragment The custom dialog to use for fingerprint login
         * @return This Builder to allow for method chaining
         */
        fun withCustomDialog(surelockFragment: SurelockFragment): Builder {
            this.surelockFragment = surelockFragment
            return this
        }

        /**
         * Indicates the tag to use for the SurelockFragment. This method MUST be called before
         * enrolling and logging in.
         *
         * @param surelockFragmentTag The tag to use
         * @return This Builder to allow for method chaining
         */
        fun withSurelockFragmentTag(surelockFragmentTag: String): Builder {
            this.surelockFragmentTag = surelockFragmentTag
            return this
        }

        /**
         * Indicates the fragment manager to use to manage the SurelockFragment. This method MUST
         * be called before enrolling and logging in.
         *
         * @param fragmentManager The fragment manager to use
         * @return This Builder to allow for method chaining
         */
        fun withFragmentManager(fragmentManager: FragmentManager): Builder {
            this.fragmentManager = fragmentManager
            return this
        }

        /**
         * Indicates the alias to use for the keystore when using fingerprint login. This method
         * MUST be called before enrolling and logging in.
         *
         * @param keyStoreAlias The keystore alias to use
         * @return This Builder to allow for method chaining
         */
        fun withKeystoreAlias(keyStoreAlias: String): Builder {
            this.keyStoreAlias = keyStoreAlias
            return this
        }

        /**
         * Indicates the SurelockStorage instance to use with fingerprint login. This method MUST
         * be called before enrolling and logging in.
         *
         * @param storage The SurelockStorage instance to use
         * @return This Builder to allow for method chaining
         */
        fun withSurelockStorage(storage: SurelockStorage): Builder {
            this.storage = storage
            return this
        }

        /**
         * Creates the Surelock instance
         */
        fun build(): Surelock {
            checkFields()
            return Surelock.initialize(this)
        }

        private fun checkFields() {
            if (keyStoreAlias.isNullOrEmpty()) {
                throw IllegalStateException("The keystore alias cannot be empty.")
            }
            if (storage == null) {
                throw IllegalStateException("SurelockStorage cannot be null.")
            }
            if (surelockFragmentTag.isNullOrEmpty()) {
                throw IllegalStateException("The dialog fragment tag cannot be empty.")
            }
            if (fragmentManager == null) {
                throw IllegalStateException("The fragment manager cannot be empty.")
            }
        }

    }

    companion object {

        private val KEY_INIT_IALIZ_ATION_VEC_TOR = "com.smashingboxes.surelock.KEY_INIT_IALIZ_ATION_VEC_TOR"
        private val TAG = Surelock::class.java.simpleName
        const val SYMMETRIC = 0
        const val ASYMMETRIC = 1

        internal fun initialize(builder: Builder): Surelock {
            return Surelock(builder)
        }

        /**
         * Check if user's device has fingerprint hardware
         *
         * @return true if fingerprint hardware is detected
         */
        fun hasFingerprintHardware(context: Context): Boolean {
            return FingerprintManagerCompat.from(context).isHardwareDetected
        }

        /**
         * Check if fingerprints have been set up for the user's device
         *
         * @return true if fingerprints have been enrolled. Otherwise, false.
         */
        fun hasUserEnrolledFingerprints(context: Context): Boolean {
            return FingerprintManagerCompat.from(context).hasEnrolledFingerprints()
        }

        /**
         * Check if user has set a Screen Lock via PIN, pattern or password for the device
         * or a SIM card is currently locked
         *
         * @return true if user has set one of these screen lock methods or if the SIM card is locked.
         */
        fun hasUserEnabledSecureLock(context: Context): Boolean {
            val keyguardManager = context.getSystemService(KeyguardManager::class.java)
            return keyguardManager.isKeyguardSecure
        }

        /**
         * Check if user has all of the necessary setup to allow fingerprint authentication
         * to be used for this application
         *
         * @param showMessaging set to true if you want Surelock to handle messaging for you.
         * It is recommended to set this to true.
         * @return true if user has fingerprint hardware, has enabled secure lock, and has enrolled fingerprints
         */
        fun fingerprintAuthIsSetUp(context: Context, showMessaging: Boolean): Boolean {
            if (!hasFingerprintHardware(context)) {
                return false
            }
            if (!hasUserEnabledSecureLock(context)) {
                if (showMessaging) {
                    // Show a message telling the user they haven't set up a fingerprint or lock screen.
                    Toast.makeText(context,
                        context.getString(R.string.error_toast_user_enable_securelock),
                        Toast.LENGTH_LONG).show()
                    context.startActivity(
                        Intent(android.provider.Settings.ACTION_SECURITY_SETTINGS))
                }
                return false
            }
            if (!hasUserEnrolledFingerprints(context)) {
                if (showMessaging) {
                    // This happens when no fingerprints are registered.
                    Toast.makeText(context, R.string.error_toast_user_enroll_fingerprints,
                        Toast.LENGTH_LONG).show()
                    context.startActivity(
                        Intent(android.provider.Settings.ACTION_SECURITY_SETTINGS))
                }
                return false
            }
            return true
        }
    }

}
