package com.smashingboxes.surelockdemo

import android.content.Context
import android.content.Intent
import android.os.Bundle
import androidx.appcompat.app.AppCompatActivity
import kotlinx.android.synthetic.main.activity_main.*
import kotlinx.android.synthetic.main.content_main.*

/**
 * Created by Tyler McCraw on 2/17/17.
 *
 *
 * A dummy activity which will be shown after user
 * has been authenticated on login screen.
 *
 */

class MainActivity : AppCompatActivity() {
    private var usernameBefore: String? = null
    private var passwordBefore: String? = null
    private var encryptedValue: String? = null
    private var usernameAfter: String? = null
    private var passwordAfter: String? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)
        setSupportActionBar(toolbar)

        usernameBefore = savedInstanceState?.getString(
            KEY_USERNAME_BEFORE) ?: intent.getStringExtra(KEY_USERNAME_BEFORE)
        passwordBefore = savedInstanceState?.getString(
            KEY_PASSWORD_BEFORE) ?: intent.getStringExtra(KEY_PASSWORD_BEFORE)
        encryptedValue = savedInstanceState?.getString(
            KEY_ENCRYPTED_VALUE) ?: intent.getStringExtra(KEY_ENCRYPTED_VALUE)
        usernameAfter = savedInstanceState?.getString(KEY_USERNAME_AFTER) ?: intent.getStringExtra(
            KEY_USERNAME_AFTER)
        passwordAfter = savedInstanceState?.getString(KEY_PASSWORD_AFTER) ?: intent.getStringExtra(
            KEY_PASSWORD_AFTER)

        confirmation.text = getString(R.string.confirmation, usernameBefore, passwordBefore,
            encryptedValue, usernameAfter, passwordAfter)
    }

    override fun onSaveInstanceState(outState: Bundle) {
        outState.apply {
            putString(KEY_USERNAME_BEFORE, usernameBefore)
            putString(KEY_PASSWORD_BEFORE, passwordBefore)
            putString(KEY_ENCRYPTED_VALUE, encryptedValue)
            putString(KEY_USERNAME_AFTER, usernameAfter)
            putString(KEY_PASSWORD_AFTER, passwordAfter)
        }
        super.onSaveInstanceState(outState)
    }

    companion object {

        // This is just for show. Never pass usernames and passwords around like this.
        private val KEY_USERNAME_BEFORE = "com.smashingboxes.surelockdemo.MainActivity.USERNAMEBEFORE"
        private val KEY_PASSWORD_BEFORE = "com.smashingboxes.surelockdemo.MainActivity.PASSWORDBEFORE"
        private val KEY_ENCRYPTED_VALUE = "com.smashingboxes.surelockdemo.MainActivity.ENCRYPTEDVALUE"
        private val KEY_USERNAME_AFTER = "com.smashingboxes.surelockdemo.MainActivity.USERNAMEAFTER"
        private val KEY_PASSWORD_AFTER = "com.smashingboxes.surelockdemo.MainActivity.PASSWORDAFTER"

        fun start(context: Context, usernameBefore: String, passwordBefore: String,
                  encryptedValue: String, usernameAfter: String, passwordAfter: String) {
            val starter = Intent(context, MainActivity::class.java).apply {
                putExtra(KEY_USERNAME_BEFORE, usernameBefore)
                putExtra(KEY_PASSWORD_BEFORE, passwordBefore)
                putExtra(KEY_ENCRYPTED_VALUE, encryptedValue)
                putExtra(KEY_USERNAME_AFTER, usernameAfter)
                putExtra(KEY_PASSWORD_AFTER, passwordAfter)
            }
            context.startActivity(starter)
        }
    }
}
