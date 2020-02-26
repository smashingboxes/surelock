package com.smashingboxes.surelock;

import androidx.annotation.CheckResult;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import java.util.Set;

/**
 * Created by Tyler McCraw on 3/5/17.
 * <p>
 *     Persistence management interface required for Surelock
 *     to store encrypted objects based on fingerprint authentication
 * </p>
 */

public interface SurelockStorage {

    void createOrUpdate(String key, @NonNull byte[] objectToStore);

    @CheckResult
    @Nullable
    byte[] get(@NonNull String key);

    void remove(String key);

    void clearAll();

    @CheckResult
    @Nullable
    Set<String> getKeys();
}
