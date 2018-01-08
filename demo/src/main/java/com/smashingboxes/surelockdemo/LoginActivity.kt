package com.smashingboxes.surelockdemo

import android.animation.Animator
import android.animation.AnimatorListenerAdapter
import android.content.Context
import android.content.SharedPreferences
import android.os.AsyncTask
import android.os.Bundle
import android.support.v7.app.AlertDialog
import android.support.v7.app.AppCompatActivity
import android.text.TextUtils
import android.util.Log
import android.view.View
import android.view.inputmethod.EditorInfo
import android.widget.Button
import android.widget.TextView
import android.widget.Toast
import com.smashingboxes.surelock.*
import kotlinx.android.synthetic.main.activity_login.*
import java.io.UnsupportedEncodingException

/**
 * Created by Tyler McCraw on 2/17/17.
 *
 *
 * A login screen that offers login via username/password
 * along with the option to set up future fingerprint authentication.
 *
 */

class LoginActivity : AppCompatActivity(), SurelockFingerprintListener {

    private var authTask: UserLoginTask? = null
    private var surelock: Surelock? = null
    private var surelockStorage: SurelockStorage? = null
    private var preferences: SharedPreferences? = null

    private val preferenceHelper: SharedPreferences
        get() {
            if (preferences == null) {
                preferences = getSharedPreferences(SHARED_PREFS_FILE_NAME, Context.MODE_PRIVATE)
            }
            return preferences!!
        }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_login)
        surelockStorage = SharedPreferencesStorage(this, SHARED_PREFS_FILE_NAME)
        setUpViews()
    }

    private fun setUpViews() {
        password.setOnEditorActionListener(
            TextView.OnEditorActionListener { _, id, _ ->
                if (id == R.id.login || id == EditorInfo.IME_NULL) {
                    handleLoginClick()
                    return@OnEditorActionListener true
                }
                false
            })

        val signInButton = findViewById<View>(R.id.sign_in_button) as Button
        signInButton.setOnClickListener { handleLoginClick() }
    }

    override fun onResume() {
        super.onResume()
        if (userWantsToUseFingerprintToLogin()) {
            if (!Surelock.fingerprintAuthIsSetUp(this, true)) {
                fingerprint_checkbox.visibility = View.VISIBLE
                fingerprint_checkbox.isChecked = false
            } else {
                try {
                    getSurelock().loginWithFingerprint(KEY_CRE_DEN_TIALS)
                } catch (e: SurelockInvalidKeyException) {
                    surelockStorage!!.clearAll()
                    showFingerprintLoginInvalidated()
                }

                fingerprint_checkbox.visibility = View.GONE
            }
        }
    }

    private fun getSurelock(): Surelock {
        if (surelock == null) {
            surelock = Surelock.Builder(this)
                .withDefaultDialog(R.style.SurelockDemoDialog)
                .withKeystoreAlias(KEYSTORE_KEY_ALIAS)
                .withFragmentManager(fragmentManager)
                .withSurelockFragmentTag(FINGERPRINT_DIALOG_FRAGMENT_TAG)
                .withSurelockStorage(surelockStorage!!)
                .build()
        }
        return surelock!!
    }

    private fun showFingerprintLoginInvalidated() {
        val builder = AlertDialog.Builder(this)
        builder.setTitle(R.string.sl_login_error)
            .setMessage(R.string.sl_re_enroll)
            .setPositiveButton(android.R.string.ok) { dialog, _ -> dialog.dismiss() }.show()
    }

    private fun userWantsToUseFingerprintToLogin(): Boolean {
        return preferenceHelper.contains(KEY_CRE_DEN_TIALS)
    }

    private fun validateLoginForm(usernameInput: String?, passwordInput: String?): Boolean {
        var errorsExist = false
        var focusView: View? = null

        if (TextUtils.isEmpty(usernameInput)) {
            username_input_layout.error = getString(R.string.error_field_required)
            focusView = username
            errorsExist = true
        } else {
            username_input_layout.error = null
        }

        if (TextUtils.isEmpty(passwordInput)) {
            password_input_layout.error = getString(R.string.error_field_required)
            focusView = password
            errorsExist = true
        } else {
            password_input_layout.error = null
        }

        if (errorsExist) {
            focusView!!.requestFocus()
        }
        return errorsExist
    }

    private fun handleLoginClick() {
        val username = username.text.toString()
        val password = password.text.toString()

        if (fingerprint_checkbox.isChecked && Surelock.fingerprintAuthIsSetUp(this, true)) {
            attemptLoginForFingerprintEnrollment(username, password)
        } else {
            attemptLogin(username, password)
        }
    }

    private fun attemptLogin(usernameInput: String?, passwordInput: String?) {
        // Don't allow multiple login attempts in a row
        if (authTask != null) {
            return
        }

        if (!validateLoginForm(usernameInput, passwordInput)) {
            showProgress(true)

            authTask = UserLoginTask(false)
            //We're just fetching this to show you on the next screen for demo purposes.
            var storedEncryptedValueString = ""
            try {
                val storedEncryptedValue = surelockStorage!!.get(KEY_CRE_DEN_TIALS)
                if (storedEncryptedValue != null) {
                    storedEncryptedValueString = String(storedEncryptedValue, Charsets.UTF_8)
                }
            } catch (e: UnsupportedEncodingException) {
                Log.d(TAG, "attemptLogin: cannot fetch encrypted credentials")
            }

            authTask!!.execute(
                username.text.toString(), password.text.toString(),
                storedEncryptedValueString,
                usernameInput, passwordInput)
        }
    }

    private fun attemptLoginForFingerprintEnrollment(usernameInput: String, passwordInput: String) {
        // Don't allow multiple login attempts in a row
        if (authTask != null) {
            return
        }

        if (!validateLoginForm(usernameInput, passwordInput)) {
            showProgress(true)
            authTask = UserLoginTask(true)
            authTask!!.execute(username.text.toString(), password.text.toString())
        }
    }


    private fun showProgress(show: Boolean) {
        val shortAnimTime = resources.getInteger(android.R.integer.config_shortAnimTime)

        login_form.visibility = if (show) View.GONE else View.VISIBLE
        login_form.animate()
            .setDuration(shortAnimTime.toLong())
            .alpha((if (show) 0 else 1).toFloat())
            .setListener(object : AnimatorListenerAdapter() {
                override fun onAnimationEnd(animation: Animator) {
                    login_form.visibility = if (show) View.GONE else View.VISIBLE
                }
            })

        login_progress.visibility = if (show) View.VISIBLE else View.GONE
        login_progress.animate()
            .setDuration(shortAnimTime.toLong())
            .alpha((if (show) 1 else 0).toFloat())
            .setListener(object : AnimatorListenerAdapter() {
                override fun onAnimationEnd(animation: Animator) {
                    login_progress.visibility = if (show) View.VISIBLE else View.GONE
                }
            })
    }

    /**
     * Represents an asynchronous login/registration task
     * used to authenticate the user.
     */
    private inner class UserLoginTask(private val withFingerprintEnrollment: Boolean) :
        AsyncTask<String, Void, Array<String>>() {

        override fun doInBackground(vararg params: String): Array<String> {
            try {
                // You should add your network call to authenticate here.
                // This just "simulates" network access.
                Thread.sleep(2000)
            } catch (e: InterruptedException) {
                Log.e(TAG, "doInBackground: auth task failed", e)
            }

            return if (withFingerprintEnrollment) {
                arrayOf(params[0], params[1])
            } else {
                arrayOf(params[0], params[1], params[2], params[3], params[4])
            }
        }

        override fun onPostExecute(params: Array<String>) {
            authTask = null
            showProgress(false)
            if (withFingerprintEnrollment) {
                try {
                    getSurelock().enrollFingerprintAndStore(KEY_CRE_DEN_TIALS,
                        getFormattedCredentialsForEncryption(params[0], params[1]))
                } catch (e: UnsupportedEncodingException) {
                    Toast.makeText(this@LoginActivity, "Failed to encrypt the login",
                        Toast.LENGTH_LONG).show()
                    Log.e(TAG, "Failed to encrypt the login" + e.message)
                } catch (e: SurelockException) {
                    Toast.makeText(this@LoginActivity, e.message, Toast.LENGTH_LONG).show()
                }

            } else {
                MainActivity.start(this@LoginActivity, params[0], params[1], params[2], params[3],
                    params[4])
            }
        }

        override fun onCancelled() {
            authTask = null
            showProgress(false)
        }
    }

    ///////////////////////////////////////////////////////////////////////////
    // FINGERPRINT AUTH
    ///////////////////////////////////////////////////////////////////////////

    override fun onFingerprintEnrolled() {
        //We're just fetching this to show you on the next screen for demo purposes.
        var storedEncryptedValueString = ""
        try {
            val storedEncryptedValue = surelockStorage!!.get(KEY_CRE_DEN_TIALS)
            if (storedEncryptedValue != null) {
                storedEncryptedValueString = String(storedEncryptedValue, Charsets.UTF_8)
            }
        } catch (e: UnsupportedEncodingException) {
            Log.d(TAG, "attemptLogin: cannot fetch encrypted credentials")
        }

        MainActivity.start(this@LoginActivity, username.text.toString(),
            password.text.toString(),
            storedEncryptedValueString, username.text.toString(),
            password.text.toString())
    }

    override fun onFingerprintAuthenticated(decryptedValue: ByteArray) {
        var username: String? = null
        var password: String? = null

        try {
            val decryptedString = String(decryptedValue, Charsets.UTF_8)
            if (!TextUtils.isEmpty(decryptedString)) {
                username = getUsernameFromFormattedCredentials(decryptedString)
                password = getPasswordFromFormattedCredentials(decryptedString)
            }
            attemptLogin(username, password)

        } catch (e: UnsupportedEncodingException) {
            Log.e(TAG, "onFingerprintAuthenticated: failed to parse decrypted credentials", e)
            onFingerprintError("Failed to parse decrypted credentials")
        }

    }

    override fun onFingerprintError(errorMessage: CharSequence?) {
        //TODO pass in the TYPE of error here. Allow user to customize message they want to display based on type of error
        //TODO reload view without surelock dialog - fall back on password login
        Toast.makeText(this, errorMessage, Toast.LENGTH_LONG).show()
    }

    @Throws(UnsupportedEncodingException::class)
    private fun getFormattedCredentialsForEncryption(username: String,
                                                     password: String): ByteArray {
        val creds = String.format("%s]%s", username, password) //TODO move delimiter to constant
        return creds.toByteArray(Charsets.UTF_8)
    }

    private fun getUsernameFromFormattedCredentials(formattedCredentials: String): String {
        val credentials = formattedCredentials.split(
            "]".toRegex()).dropLastWhile { it.isEmpty() }.toTypedArray()
        return credentials[0]
    }

    private fun getPasswordFromFormattedCredentials(formattedCredentials: String): String {
        val credentials = formattedCredentials.split(
            "]".toRegex()).dropLastWhile { it.isEmpty() }.toTypedArray()
        return credentials[1]
    }

    companion object {

        private val TAG = LoginActivity::class.java.simpleName
        private val FINGERPRINT_DIALOG_FRAGMENT_TAG = "com.smashingboxes.surelockdemo.FINGERPRINT_DIALOG_FRAGMENT_TAG"
        private val KEYSTORE_KEY_ALIAS = "com.smashingboxes.surelockdemo.KEYSTORE_KEY_ALIAS"
        private val KEY_CRE_DEN_TIALS = "com.smashingboxes.surelockdemo.KEY_CRE_DEN_TIALS"
        private val SHARED_PREFS_FILE_NAME = "surelock_demo_prefs"
    }
}