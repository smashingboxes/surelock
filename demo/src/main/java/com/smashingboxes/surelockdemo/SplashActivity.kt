package com.smashingboxes.surelockdemo

import android.content.Intent
import android.os.Bundle
import android.support.v7.app.AppCompatActivity

/**
 * Created by Nicholas Cook on 1/8/18.
 * <p>
 *     A splash screen to display while the app starts from cold boot.
 * </p>
 */
class SplashActivity : AppCompatActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        startActivity(Intent(this, LoginActivity::class.java))
    }
}