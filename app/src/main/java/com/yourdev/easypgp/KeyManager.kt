package com.yourdev.easypgp

import android.content.Context
import android.content.SharedPreferences
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import com.google.gson.Gson
import com.google.gson.reflect.TypeToken
import com.yourdev.easypgp.PGPUtil.PGPKeyPair
import org.bouncycastle.openpgp.PGPObjectFactory
import org.bouncycastle.openpgp.PGPPublicKeyRing
import org.bouncycastle.openpgp.PGPSecretKeyRing
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator
import java.io.ByteArrayInputStream
import java.security.KeyStore
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import androidx.core.content.edit

class KeyManager(context: Context) {

    private val prefs: SharedPreferences = context.getSharedPreferences("pgp_keys", Context.MODE_PRIVATE)
    private val gson = Gson()
    private val keyStore: KeyStore = KeyStore.getInstance("AndroidKeyStore")
    private val keyAlias = "EasyPGP_PrivateKey_Encryption_Key"

    init {
        keyStore.load(null)
        loadMyKeyPair()
    }

    data class StoredKey(
        val name: String,
        val keyId: String,
        val keyString: String
    )

    data class EncryptedData(
        val encryptedData: String,
        val iv: String
    )

    /**
     * Encrypts and stores the private key using AES-256-GCM encryption
     * Uses Android KeyStore for secure key management
     */
    fun encryptPrivateKeyAndStore(privatekey: String?, password: String?) {
        if (privatekey == null) {
            throw IllegalArgumentException("Private key cannot be null")
        }

        try {
            // Generate or get existing encryption key from Android KeyStore
            val secretKey = getOrCreateSecretKey()

            // Encrypt the private key
            val encryptedData = encryptData(privatekey, secretKey)

            // Store encrypted private key and metadata
            prefs.edit {
                putString("my_private_key_encrypted", gson.toJson(encryptedData))
                putBoolean("keyring_locked", true)
                putBoolean("has_encrypted_key", true)
            }
        } catch (e: Exception) {
            throw Exception("Failed to encrypt and store private key: ${e.message}")
        }
    }

    /**
     * Decrypts the stored private key using the encryption key from Android KeyStore
     */
    fun decryptStoredPrivateKey(password: String?): String? {
        if (!hasEncryptedPrivateKey()) {
            return null
        }

        return try {
            // Get the encryption key from Android KeyStore
            val secretKey = getSecretKey() ?: return null

            // Get encrypted data from SharedPreferences
            val encryptedDataJson = prefs.getString("my_private_key_encrypted", null) ?: return null
            val encryptedData = gson.fromJson(encryptedDataJson, EncryptedData::class.java)

            // Decrypt the private key
            decryptData(encryptedData, secretKey)

        } catch (e: Exception) {
            null // Return null if decryption fails
        }
    }

    /**
     * Generates or retrieves the AES-256-GCM encryption key from Android KeyStore
     */
    private fun getOrCreateSecretKey(): SecretKey {
        return if (keyStore.containsAlias(keyAlias)) {
            getSecretKey()!!
        } else {
            generateSecretKey()
        }
    }

    /**
     * Generates a new AES-256-GCM key in Android KeyStore
     */
    private fun generateSecretKey(): SecretKey {
        val keyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")

        val keyGenParameterSpec = KeyGenParameterSpec.Builder(
            keyAlias,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
        )
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256) // AES-256
            .setUserAuthenticationRequired(false) // Set to true if you want biometric/PIN protection
            .build()

        keyGenerator.init(keyGenParameterSpec)
        return keyGenerator.generateKey()
    }

    /**
     * Retrieves existing encryption key from Android KeyStore
     */
    private fun getSecretKey(): SecretKey? {
        return try {
            keyStore.getKey(keyAlias, null) as SecretKey
        } catch (e: Exception) {
            null
        }
    }

    /**
     * Encrypts data using AES-256-GCM
     */
    private fun encryptData(data: String, secretKey: SecretKey): EncryptedData {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, secretKey)

        val iv = cipher.iv
        val encryptedBytes = cipher.doFinal(data.toByteArray(Charsets.UTF_8))

        return EncryptedData(
            encryptedData = Base64.encodeToString(encryptedBytes, Base64.DEFAULT),
            iv = Base64.encodeToString(iv, Base64.DEFAULT)
        )
    }

    /**
     * Decrypts data using AES-256-GCM
     */
    private fun decryptData(encryptedData: EncryptedData, secretKey: SecretKey): String {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")

        val iv = Base64.decode(encryptedData.iv, Base64.DEFAULT)
        val gcmParameterSpec = GCMParameterSpec(128, iv) // 128-bit authentication tag

        cipher.init(Cipher.DECRYPT_MODE, secretKey, gcmParameterSpec)

        val encryptedBytes = Base64.decode(encryptedData.encryptedData, Base64.DEFAULT)
        val decryptedBytes = cipher.doFinal(encryptedBytes)

        return String(decryptedBytes, Charsets.UTF_8)
    }

    /**
     * Checks if an encrypted private key exists
     */
    private fun hasEncryptedPrivateKey(): Boolean {
        return prefs.getBoolean("has_encrypted_key", false) &&
               prefs.getString("my_private_key_encrypted", null) != null
    }

    /**
     * Clears the encryption key from Android KeyStore
     */
    fun clearEncryptionKey() {
        try {
            if (keyStore.containsAlias(keyAlias)) {
                keyStore.deleteEntry(keyAlias)
            }
            prefs.edit {
                remove("my_private_key_encrypted")
                putBoolean("has_encrypted_key", false)
                putBoolean("keyring_locked", true)
            }
        } catch (e: Exception) {
            throw Exception("Failed to clear encryption key: ${e.message}")
        }
    }

    public fun isKeyringLocked(): Boolean {
        var privkey: String =           prefs.getString("my_private_key", "").toString();
        val privkey_encrypted: String = prefs.getString("my_private_key_encrypted", "").toString();
        if (privkey.length >= 0) {
            if(privkey_encrypted !== "")
                return true
            else
                return false
        }
        else {
            return true
        }
    }
    public fun unlockKeyring() {
        prefs.edit {
            putBoolean("keyring_locked", false)
        }
    }
    public fun lockKeyring() {
        prefs.edit {
            putBoolean("keyring_locked", true)
        }
    }

    // Remove unencrypted private key when encrypting
    fun removeUnencryptedPrivateKey() {
        prefs.edit {
            remove("my_private_key_unencrypted")
        }
    }

    // Save user's own PGP key pair
    fun saveMyKeyPair(keyPair: PGPKeyPair) {
        try {
            val publicKeyString = String(keyPair.publicKeyRing.encoded)
            val privateKeyString = String(keyPair.secretKeyRing.encoded)

            // Save both public key and unencrypted private key initially
            prefs.edit()
                .putString("my_public_key", publicKeyString)
                .putString("my_private_key_unencrypted", privateKeyString)
                .putBoolean("has_my_keys", true)
                .apply()

        } catch (e: Exception) {
            throw Exception("Failed to save key pair: ${e.message}")
        }
    }

    // Load user's own PGP key pair
    fun loadMyKeyPair(): PGPKeyPair? {
        val publicKeyString = prefs.getString("my_public_key", null) ?: return null

        // Try to get private key - first check if we have an unencrypted version
        val privateKeyString = if (prefs.contains("my_private_key_unencrypted")) {
            // We have unencrypted private key (fresh install or unlocked state)
            prefs.getString("my_private_key_unencrypted", null)
        } else {
            // Try to decrypt stored encrypted private key
            decryptStoredPrivateKey(null)
        }

        if (privateKeyString == null) {
            return null
        }

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
            .remove("my_private_key_unencrypted")
            .putBoolean("has_my_keys", false)
            .apply()

        // Also clear encrypted private key
        clearEncryptionKey()
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

    // Get stored public key string
    fun getStoredPublicKey(): String? {
        return prefs.getString("my_public_key", null)
    }

    // Reconstruct PGP key pair from string representations
    fun reconstructKeyPairFromStrings(publicKeyString: String, privateKeyString: String): PGPKeyPair? {
        return try {
            val publicKeyRing = parsePublicKeyRing(publicKeyString)
            val secretKeyRing = parseSecretKeyRing(privateKeyString)
            val publicKey = publicKeyRing.publicKey

            PGPKeyPair(publicKey, publicKeyRing, secretKeyRing)
        } catch (e: Exception) {
            null
        }
    }

    fun setUseSamePassword(enabled: Boolean) {
        prefs.edit { putBoolean("use_same_password", enabled) }
    }

    fun isUseSamePassword(): Boolean {
        return prefs.getBoolean("use_same_password", false)
    }
}
