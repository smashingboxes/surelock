package com.smashingboxes.surelock;

import android.content.Context;
import android.content.SharedPreferences;
import android.support.annotation.NonNull;
import android.support.annotation.Nullable;
import android.text.TextUtils;
import android.util.Base64;

import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.Set;

/**
 * Created by Tyler McCraw on 3/5/17.
 * <p>
 *     Storage mechanism used by Surelock in order to
 *     persist encrypted objects in SharedPreferences by default
 * </p>
 */

public class SharedPreferencesStorage implements SurelockStorage {

    private SharedPreferences preferences;
    private final Context context;
    private final String prefsName;

    /**
     * Create a new SurelockStorage which uses SharedPreferences for persistence
     *
     * @param context context
     * @param prefsName Desired preferences file.
     */
    public SharedPreferencesStorage(Context context, String prefsName) {
        this.context = context;
        this.prefsName = prefsName;
    }

    private synchronized SharedPreferences getPrefs() {
        if (preferences == null) {
            preferences = context.getSharedPreferences(prefsName, Context.MODE_PRIVATE);
        }
        return preferences;
    }

    @Override
    public void createOrUpdate(String key, @NonNull byte[] objectToStore) {
        String encodedString = Base64.encodeToString(objectToStore, Base64.DEFAULT);
        getPrefs().edit().putString(key, encodedString).apply();
    }

    @Nullable
    @Override
    public byte[] get(@NonNull String key) {
        String byteString = getPrefs().getString(key, null);
        byte[] decodedBytes = null;
        if (!TextUtils.isEmpty(byteString)) {
            decodedBytes = Base64.decode(byteString, Base64.DEFAULT);
        }
        return decodedBytes;
    }

    @Override
    public void remove(String key) {
        getPrefs().edit().remove(key).apply();
    }

    @Override
    public void clearAll() {
        getPrefs().edit().clear().apply();
    }

    @Nullable
    @Override
    public Set<String> getKeys() {
        return Collections.unmodifiableSet(new LinkedHashSet<>(getPrefs().getAll().keySet()));
    }
}
