package com.smashingboxes.surelockdemo;

import android.content.Context;
import android.content.Intent;
import android.os.Bundle;
import android.support.annotation.NonNull;
import android.support.v7.app.AppCompatActivity;
import android.support.v7.widget.Toolbar;
import android.widget.TextView;

/**
 * Created by Tyler McCraw on 2/17/17.
 * <p>
 *     A dummy activity which will be shown after user
 *     has been authenticated on login screen.
 * </p>
 */

public class MainActivity extends AppCompatActivity {

    // This is just for show. Never pass usernames and passwords around like this.
    private static final String KEY_USERNAME_BEFORE = "com.smashingboxes.surelockdemo.MainActivity.USERNAMEBEFORE";
    private static final String KEY_PASSWORD_BEFORE = "com.smashingboxes.surelockdemo.MainActivity.PASSWORDBEFORE";
    private static final String KEY_ENCRYPTED_VALUE = "com.smashingboxes.surelockdemo.MainActivity.ENCRYPTEDVALUE";
    private static final String KEY_USERNAME_AFTER = "com.smashingboxes.surelockdemo.MainActivity.USERNAMEAFTER";
    private static final String KEY_PASSWORD_AFTER = "com.smashingboxes.surelockdemo.MainActivity.PASSWORDAFTER";
    private String usernameBefore;
    private String passwordBefore;
    private String encryptedValue;
    private String usernameAfter;
    private String passwordAfter;

    public static void start(Context context,
                             @NonNull String usernameBefore, @NonNull String passwordBefore,
                             @NonNull String encryptedValue,
                             @NonNull String usernameAfter, @NonNull String passwordAfter) {
        Intent starter = new Intent(context, MainActivity.class);
        starter.putExtra(KEY_USERNAME_BEFORE, usernameBefore);
        starter.putExtra(KEY_PASSWORD_BEFORE, passwordBefore);
        starter.putExtra(KEY_ENCRYPTED_VALUE, encryptedValue);
        starter.putExtra(KEY_USERNAME_AFTER, usernameAfter);
        starter.putExtra(KEY_PASSWORD_AFTER, passwordAfter);
        context.startActivity(starter);
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        Toolbar toolbar = (Toolbar) findViewById(R.id.toolbar);
        setSupportActionBar(toolbar);

        if (savedInstanceState != null) {
            usernameBefore = savedInstanceState.getString(KEY_USERNAME_BEFORE);
            passwordBefore = savedInstanceState.getString(KEY_PASSWORD_BEFORE);
            encryptedValue = savedInstanceState.getString(KEY_ENCRYPTED_VALUE);
            usernameAfter = savedInstanceState.getString(KEY_USERNAME_AFTER);
            passwordAfter = savedInstanceState.getString(KEY_PASSWORD_AFTER);
        } else {
            usernameBefore = getIntent().getStringExtra(KEY_USERNAME_BEFORE);
            passwordBefore = getIntent().getStringExtra(KEY_PASSWORD_BEFORE);
            encryptedValue = getIntent().getStringExtra(KEY_ENCRYPTED_VALUE);
            usernameAfter = getIntent().getStringExtra(KEY_USERNAME_AFTER);
            passwordAfter = getIntent().getStringExtra(KEY_PASSWORD_AFTER);
        }

        TextView confirmation = (TextView) findViewById(R.id.confirmation);
        confirmation.setText(getString(R.string.confirmation,
                usernameBefore, passwordBefore,
                encryptedValue,
                usernameAfter, passwordAfter));
    }

    @Override
    protected void onSaveInstanceState(Bundle outState) {
        outState.putString(KEY_USERNAME_BEFORE, usernameBefore);
        outState.putString(KEY_PASSWORD_BEFORE, passwordBefore);
        outState.putString(KEY_ENCRYPTED_VALUE, encryptedValue);
        outState.putString(KEY_USERNAME_AFTER, usernameAfter);
        outState.putString(KEY_PASSWORD_AFTER, passwordAfter);
        super.onSaveInstanceState(outState);
    }
}
