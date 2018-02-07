package com.smashingboxes.surelock

import android.app.Dialog
import android.app.DialogFragment
import android.app.FragmentManager
import android.content.Context
import android.content.res.TypedArray
import android.os.Bundle
import android.support.annotation.StyleRes
import android.support.v4.content.ContextCompat
import android.support.v4.hardware.fingerprint.FingerprintManagerCompat
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.view.Window
import android.widget.Button
import android.widget.TextView

import com.mattprecious.swirl.SwirlView

import javax.crypto.BadPaddingException
import javax.crypto.Cipher
import javax.crypto.IllegalBlockSizeException

/**
 * Created by Tyler McCraw on 2/17/17.
 *
 *
 * Default login dialog which uses fingerprint APIs to authenticate the user,
 * and falls back to password authentication if fingerprint is not available.
 *
 */

class SurelockDefaultDialog : DialogFragment(), SurelockFragment {

    private var fingerprintManager: FingerprintManagerCompat? = null
    private var cryptoObject: FingerprintManagerCompat.CryptoObject? = null
    private var keyForDecryption: String? = null
    private var valueToEncrypt: ByteArray? = null
    private var storage: SurelockStorage? = null
    private var listener: SurelockFingerprintListener? = null
    private var uiHelper: SurelockFingerprintUiHelper? = null
    private var cipherOperationMode: Int = 0
    @StyleRes
    private var styleId: Int = 0

    // TODO  clean up and genericize default dialog - add custom attribute set which can be overridden
    private var iconView: SwirlView? = null
    private var statusTextView: TextView? = null

    private val resetErrorTextRunnable = Runnable {
        if (isAdded) {
            statusTextView?.apply {
                setTextColor(ContextCompat.getColor(activity, R.color.hint_grey))
                text = resources.getString(R.string.fingerprint_hint)
            }
            iconView?.setState(SwirlView.State.ON)
        }
    }

    override fun init(fingerprintManager: FingerprintManagerCompat,
                      cryptoObject: FingerprintManagerCompat.CryptoObject,
                      key: String, storage: SurelockStorage, valueToEncrypt: ByteArray?) {
        this.cryptoObject = cryptoObject
        this.fingerprintManager = fingerprintManager
        this.keyForDecryption = key //TODO need to be passing these as newInstance params... or figure a better way to do this
        this.storage = storage
        this.valueToEncrypt = valueToEncrypt
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        uiHelper = SurelockFingerprintUiHelper(fingerprintManager!!, this)

        // Do not create a new Fragment when the Activity is re-created such as orientation changes.
        retainInstance = true

        if (savedInstanceState != null) {
            cipherOperationMode = savedInstanceState.getInt(KEY_CIPHER_OP_MODE)
            styleId = savedInstanceState.getInt(KEY_STYLE_ID)
        } else {
            cipherOperationMode = arguments.getInt(KEY_CIPHER_OP_MODE)
            styleId = arguments.getInt(KEY_STYLE_ID)
        }

        val attrs = activity.obtainStyledAttributes(styleId, R.styleable
            .SurelockDefaultDialog)
        val dialogTheme = attrs.getResourceId(R.styleable.SurelockDefaultDialog_sl_dialog_theme, 0)
        attrs.recycle()

        setStyle(DialogFragment.STYLE_NO_TITLE,
            if (dialogTheme == 0) R.style.SurelockTheme_NoActionBar else dialogTheme)
    }

    override fun onCreateView(inflater: LayoutInflater, container: ViewGroup?,
                              savedInstanceState: Bundle?): View? {
        val view = inflater.inflate(R.layout.fingerprint_dialog_container, container, false)
        val attrs = activity.obtainStyledAttributes(styleId, R.styleable.SurelockDefaultDialog)

        setUpViews(view, attrs)

        attrs.recycle()

        return view
    }

    private fun setUpViews(fragmentView: View, attrs: TypedArray) {
        iconView = fragmentView.findViewById<View>(R.id.fingerprint_icon) as SwirlView
        statusTextView = fragmentView.findViewById<View>(R.id.fingerprint_status) as TextView
        val fallbackButton = fragmentView.findViewById<View>(R.id.fallback_button) as Button
        fallbackButton.setOnClickListener { dismiss() }

        val fallbackButtonText = attrs.getString(R.styleable
            .SurelockDefaultDialog_sl_fallback_button_text)
        val fallbackButtonColor = attrs.getColor(R.styleable
            .SurelockDefaultDialog_sl_fallback_button_background, 0)
        val fallbackButtonTextColor = attrs.getColor(R.styleable
            .SurelockDefaultDialog_sl_fallback_button_text_color, 0)
        fallbackButton.text = fallbackButtonText
        if (fallbackButtonColor != 0) {
            fallbackButton.setBackgroundColor(fallbackButtonColor)
        }
        if (fallbackButtonTextColor != 0) {
            fallbackButton.setTextColor(fallbackButtonTextColor)
        }

        val titleBar = fragmentView.findViewById<View>(R.id.sl_title_bar) as TextView
        val titleBarText = attrs.getString(R.styleable.SurelockDefaultDialog_sl_title_bar_text)
        titleBar.text = titleBarText
        val titleBarColor = attrs.getColor(R.styleable
            .SurelockDefaultDialog_sl_title_bar_background, 0)
        val titleBarTextColor = attrs.getColor(R.styleable
            .SurelockDefaultDialog_sl_title_bar_text_color, 0)
        if (titleBarColor != 0) {
            titleBar.setBackgroundColor(titleBarColor)
        }
        if (titleBarTextColor != 0) {
            titleBar.setTextColor(titleBarTextColor)
        }

    }

    override fun onCreateDialog(savedInstanceState: Bundle?): Dialog {
        val dialog = super.onCreateDialog(savedInstanceState)
        dialog.requestWindowFeature(Window.FEATURE_NO_TITLE)
        return dialog
    }

    override fun onAttach(context: Context) {
        super.onAttach(context)
        if (context is SurelockFingerprintListener) {
            listener = context
        } else {
            throw RuntimeException(
                context.toString() + " must implement SurelockFingerprintListener")
        }
    }

    override fun onResume() {
        super.onResume()
        uiHelper?.startListening(cryptoObject!!)
        iconView?.setState(SwirlView.State.ON)
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
        outState.putInt(KEY_STYLE_ID, styleId)
        super.onSaveInstanceState(outState)
    }

    override fun onAuthenticationSucceeded(result: FingerprintManagerCompat.AuthenticationResult?) {
        iconView?.postDelayed({
            //TODO figure out a way to not make user have to run encryption/decryption themselves here
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

    override fun onAuthenticationError(errorCode: Int, errString: CharSequence?) {
        showError(errString)
        listener?.onFingerprintError(errString)
        dismiss()
    }

    override fun onAuthenticationHelp(helpCode: Int, helpString: CharSequence?) {
        showError(helpString)
        listener?.onFingerprintError(helpString)
    }

    override fun onAuthenticationFailed() {
        showError(statusTextView!!.resources.getString(R.string.fingerprint_not_recognized))
        listener?.onFingerprintError(null)
    }

    private fun showError(error: CharSequence?) {
        iconView?.setState(SwirlView.State.ERROR)
        statusTextView?.apply {
            text = error
            setTextColor(ContextCompat.getColor(activity, R.color.error_red))
            removeCallbacks(resetErrorTextRunnable)
            postDelayed(resetErrorTextRunnable, ERROR_TIMEOUT_MILLIS)
        }
    }

    companion object {

        private val KEY_CIPHER_OP_MODE = "com.smashingboxes.surelock.SurelockDefaultDialog.KEY_CIPHER_OP_MODE"
        private val KEY_STYLE_ID = "com.smashingboxes.surelock.KEY_STYLE_ID"

        private val ERROR_TIMEOUT_MILLIS: Long = 1600
        private val SUCCESS_DELAY_MILLIS: Long = 1300 //TODO make these configurable via attrs

        internal fun newInstance(cipherOperationMode: Int,
                                 @StyleRes styleId: Int): SurelockDefaultDialog {
            val args = Bundle()
            args.putInt(KEY_CIPHER_OP_MODE, cipherOperationMode)
            args.putInt(KEY_STYLE_ID, styleId)

            return SurelockDefaultDialog().apply {
                arguments = args
            }
        }
    }
}
