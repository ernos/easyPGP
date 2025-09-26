package com.yourdev.easypgp

import android.content.Context
import android.content.SharedPreferences
import com.google.gson.Gson
import com.google.gson.reflect.TypeToken
import com.yourdev.easypgp.PGPUtil.PGPKeyPair
import org.bouncycastle.openpgp.PGPObjectFactory
import org.bouncycastle.openpgp.PGPPublicKeyRing
import org.bouncycastle.openpgp.PGPSecretKeyRing
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator
import java.io.ByteArrayInputStream
import androidx.core.content.edit

class KeyManager(context: Context) {

    private val prefs: SharedPreferences = context.getSharedPreferences("pgp_keys", Context.MODE_PRIVATE)
    private val gson = Gson()

    data class StoredKey(
        val name: String,
        val keyId: String,
        val keyString: String
    )

    public fun encryptPrivateKeyAndStore(privatekey: String? = null, password: String? = null) {
        try {

            prefs.edit {
                putString("my_private_key", privatekey)
                    .putBoolean("keyring_locked", true)
            }
        } catch (e: Exception) {
            throw Exception("Failed to save key pair: ${e.message}")
        }
    }
    public fun DecryptStoredPrivateKey(password: String? = null): String? {
        var decryptedPrivateKeyString: String? = null;
        if(password!=null){

            var privateKeyString = prefs.getString("my_private_key", null);
            //TODO: Decrypt keyring from storage and store it decrypted in memory

            decryptedPrivateKeyString=privateKeyString;

            TODO()

        }
        return decryptedPrivateKeyString;
    }
    public fun isKeyringLocked(): Boolean {
        return prefs.getBoolean("keyring_locked", false)
    }
    // Save user's own PGP key pair
    fun saveMyKeyPair(keyPair: PGPKeyPair) {
        try {
            val publicKeyString = String(keyPair.publicKeyRing.encoded)
            val privateKeyString = String(keyPair.secretKeyRing.encoded)

            prefs.edit()
                .putString("my_public_key", publicKeyString)
                .putString("my_private_key", privateKeyString)
                .putBoolean("has_my_keys", true)
                .apply()
        } catch (e: Exception) {
            throw Exception("Failed to save key pair: ${e.message}")
        }
    }

    // Load user's own PGP key pair
    fun loadMyKeyPair(): PGPKeyPair? {
        val publicKeyString = prefs.getString("my_public_key", null) ?: return null
        val privateKeyString = prefs.getString("my_private_key", null) ?: return null

        return try {
            val publicKeyRing = parsePublicKeyRing(publicKeyString)
            val secretKeyRing = parseSecretKeyRing(privateKeyString)
            val publicKey = publicKeyRing.publicKey

            PGPKeyPair(publicKey, publicKeyRing, secretKeyRing)
        } catch (e: Exception) {
            null // Return null if parsing fails
        }
    }

    // Clear user's own keys
    fun clearMyKeys() {
        prefs.edit()
            .remove("my_public_key")
            .remove("my_private_key")
            .putBoolean("has_my_keys", false)
            .apply()
    }

    private fun parsePublicKeyRing(keyString: String): PGPPublicKeyRing {
        val inputStream = ByteArrayInputStream(keyString.toByteArray())
        val decoderStream = org.bouncycastle.openpgp.PGPUtil.getDecoderStream(inputStream)
        val pgpObjectFactory = PGPObjectFactory(decoderStream, BcKeyFingerprintCalculator())
        return pgpObjectFactory.nextObject() as PGPPublicKeyRing
    }

    private fun parseSecretKeyRing(keyString: String): PGPSecretKeyRing {
        val inputStream = ByteArrayInputStream(keyString.toByteArray())
        val decoderStream = org.bouncycastle.openpgp.PGPUtil.getDecoderStream(inputStream)
        val pgpObjectFactory = PGPObjectFactory(decoderStream, BcKeyFingerprintCalculator())
        return pgpObjectFactory.nextObject() as PGPSecretKeyRing
    }

    fun saveImportedKey(name: String, keyString: String, keyId: String) {
        val keys = getStoredKeys().toMutableList()
        keys.add(StoredKey(name, keyId, keyString))

        val keysJson = gson.toJson(keys)
        prefs.edit().putString("imported_keys", keysJson).apply()
    }

    fun getImportedKeys(): List<ImportedPublicKey> {
        return getStoredKeys().mapNotNull { storedKey ->
            try {
                val publicKey = parsePublicKey(storedKey.keyString)
                ImportedPublicKey(
                    name = storedKey.name,
                    publicKey = publicKey,
                    keyId = storedKey.keyId,
                    keyString = storedKey.keyString
                )
            } catch (e: Exception) {
                null // Skip invalid keys
            }
        }
    }

    fun removeImportedKey(keyId: String) {
        val keys = getStoredKeys().toMutableList()
        keys.removeAll { it.keyId == keyId }

        val keysJson = gson.toJson(keys)
        prefs.edit().putString("imported_keys", keysJson).apply()
    }

    private fun getStoredKeys(): List<StoredKey> {
        val keysJson = prefs.getString("imported_keys", null) ?: return emptyList()
        val type = object : TypeToken<List<StoredKey>>() {}.type
        return gson.fromJson(keysJson, type)
    }

    private fun parsePublicKey(keyString: String): org.bouncycastle.openpgp.PGPPublicKey {
        val inputStream = ByteArrayInputStream(keyString.toByteArray())
        val decoderStream = org.bouncycastle.openpgp.PGPUtil.getDecoderStream(inputStream)
        val pgpObjectFactory = PGPObjectFactory(decoderStream, BcKeyFingerprintCalculator())

        val keyRing = pgpObjectFactory.nextObject() as PGPPublicKeyRing
        return keyRing.publicKey
    }

    fun saveMyKeyStatus(hasKeys: Boolean) {
        prefs.edit().putBoolean("has_my_keys", hasKeys).apply()
    }

    fun hasMyKeys(): Boolean {
        return prefs.getBoolean("has_my_keys", false)
    }
}
