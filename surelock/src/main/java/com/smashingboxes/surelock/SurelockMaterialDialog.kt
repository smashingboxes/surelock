package com.smashingboxes.surelock

import android.app.DialogFragment
import android.app.FragmentManager
import android.content.Context
import android.os.Bundle
import android.support.v4.content.ContextCompat
import android.support.v4.hardware.fingerprint.FingerprintManagerCompat
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.Button
import android.widget.TextView

import com.mattprecious.swirl.SwirlView

import javax.crypto.BadPaddingException
import javax.crypto.Cipher
import javax.crypto.IllegalBlockSizeException

/**
 * Created by Nicholas Cook on 3/17/17.
 *
 *
 * A login dialog which follows standard Material Design guidelines. It uses
 * fingerprint APIs to authenticate the user, and falls back to password
 * authentication if fingerprint is not available.
 *
 */

class SurelockMaterialDialog : DialogFragment(), SurelockFragment {

    private var swirlView: SwirlView? = null
    private var messageView: TextView? = null

    private var fingerprintManager: FingerprintManagerCompat? = null
    private var cryptoObject: FingerprintManagerCompat.CryptoObject? = null
    private var keyForDecryption: String? = null
    private var valueToEncrypt: ByteArray? = null
    private var storage: SurelockStorage? = null
    private var listener: SurelockFingerprintListener? = null
    private var uiHelper: SurelockFingerprintUiHelper? = null
    private var cipherOperationMode: Int = 0

    private val resetErrorTextRunnable = Runnable {
        if (isAdded) {
            messageView?.apply {
                setTextColor(ContextCompat.getColor(activity, R.color.hint_grey))
                text = resources.getString(R.string.fingerprint_hint)
            }
            swirlView?.apply {
                setState(SwirlView.State.ON)
            }
        }
    }

    override fun onAttach(context: Context) {
        super.onAttach(context)
        if (context is SurelockFingerprintListener) {
            listener = context
        } else {
            throw RuntimeException(context.toString() + " must implement " +
                "SurelockFingerprintListener")
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        uiHelper = SurelockFingerprintUiHelper(fingerprintManager!!, this)

        // Do not create a new Fragment when the Activity is re-created such as orientation changes.
        retainInstance = true

        cipherOperationMode = savedInstanceState?.getInt(KEY_CIPHER_OP_MODE) ?: arguments.getInt(
            KEY_CIPHER_OP_MODE)

        setStyle(DialogFragment.STYLE_NORMAL, android.R.style.Theme_Material_Light_Dialog)
    }

    override fun onCreateView(inflater: LayoutInflater, container: ViewGroup?,
                              savedInstanceState: Bundle?): View? {
        dialog.setTitle(R.string.sl_sign_in)
        val view = inflater.inflate(R.layout.material_fingerprint_dialog, container, false)
        val cancelButton = view.findViewById<View>(R.id.cancel_button) as Button
        cancelButton.setOnClickListener { dismiss() }
        swirlView = view.findViewById<View>(R.id.fingerprint_icon) as SwirlView
        messageView = view.findViewById<View>(R.id.fingerprint_status) as TextView
        return view
    }

    override fun onResume() {
        super.onResume()
        cryptoObject?.let {
            uiHelper?.startListening(it)
        }
        swirlView?.setState(SwirlView.State.ON)
    }

    override fun show(fragmentManager: FragmentManager, fingerprintDialogFragmentTag: String) {
        if (dialog == null || !dialog.isShowing) {
            super.show(fragmentManager, fingerprintDialogFragmentTag)
        }
    }

    override fun onPause() {
        super.onPause()
        uiHelper?.stopListening()
    }

    override fun onDetach() {
        super.onDetach()
        listener = null
    }

    override fun onSaveInstanceState(outState: Bundle) {
        outState.putInt(KEY_CIPHER_OP_MODE, cipherOperationMode)
        super.onSaveInstanceState(outState)
    }

    override fun init(fingerprintManager: FingerprintManagerCompat,
                      cryptoObject: FingerprintManagerCompat.CryptoObject, key: String,
                      storage: SurelockStorage, valueToEncrypt: ByteArray?) {
        this.fingerprintManager = fingerprintManager
        this.cryptoObject = cryptoObject
        this.keyForDecryption = key
        this.storage = storage
        this.valueToEncrypt = valueToEncrypt
    }

    override fun onAuthenticationError(errorCode: Int, errString: CharSequence?) {
        showError(errString)
        listener?.onFingerprintError(errString)
        dismiss()
    }

    override fun onAuthenticationHelp(helpCode: Int, helpString: CharSequence?) {
        showError(helpString)
        listener?.onFingerprintError(helpString)
    }

    override fun onAuthenticationSucceeded(result: FingerprintManagerCompat.AuthenticationResult?) {
        swirlView?.postDelayed({
            //TODO figure out a way to not make user have to run encryption/decryption
            // themselves here
            if (Cipher.ENCRYPT_MODE == cipherOperationMode) {
                try {
                    val encryptedValue = cryptoObject?.cipher?.doFinal(valueToEncrypt)
                    keyForDecryption?.let {
                        if (encryptedValue != null) {
                            storage?.createOrUpdate(it, encryptedValue)
                            listener?.onFingerprintEnrolled()
                        }
                    }
                } catch (e: IllegalBlockSizeException) {
                    listener?.onFingerprintError(e.message)
                } catch (e: BadPaddingException) {
                    listener?.onFingerprintError(e.message)
                }

            } else if (Cipher.DECRYPT_MODE == cipherOperationMode) {
                val encryptedValue = storage?.get(keyForDecryption!!)
                val decryptedValue: ByteArray
                try {
                    decryptedValue = cryptoObject?.cipher?.doFinal(encryptedValue) ?: ByteArray(0)
                    listener?.onFingerprintAuthenticated(decryptedValue)
                } catch (e: BadPaddingException) {
                    listener?.onFingerprintError(e.message)
                } catch (e: IllegalBlockSizeException) {
                    listener?.onFingerprintError(e.message)
                }

            }
            dismiss()
        }, SUCCESS_DELAY_MILLIS)
    }

    override fun onAuthenticationFailed() {
        showError(messageView?.resources?.getString(R.string.fingerprint_not_recognized) ?: "")
        listener?.onFingerprintError(null)
    }

    private fun showError(error: CharSequence?) {
        swirlView?.setState(SwirlView.State.ERROR)
        messageView?.apply {
            text = error
            setTextColor(ContextCompat.getColor(activity, R.color.error_red))
            removeCallbacks(resetErrorTextRunnable)
            postDelayed(resetErrorTextRunnable, ERROR_TIMEOUT_MILLIS)
        }
    }

    companion object {

        private val KEY_CIPHER_OP_MODE = "com.smashingboxes.surelock" + ".SurelockMaterialDialog.KEY_CIPHER_OP_MODE"

        private val ERROR_TIMEOUT_MILLIS: Long = 1600
        private val SUCCESS_DELAY_MILLIS: Long = 1300

        internal fun newInstance(cipherOperationMode: Int): SurelockMaterialDialog {

            val args = Bundle()
            args.putInt(KEY_CIPHER_OP_MODE, cipherOperationMode)

            return SurelockMaterialDialog().apply {
                arguments = args
            }
        }
    }
}
