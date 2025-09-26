package com.yourdev.easypgp

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.os.Bundle
import android.widget.*
import androidx.appcompat.app.AppCompatActivity
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import kotlinx.coroutines.*
import org.bouncycastle.openpgp.PGPObjectFactory
import org.bouncycastle.openpgp.PGPPublicKeyRing
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator
import java.io.ByteArrayInputStream

class SettingsActivity : AppCompatActivity() {

    private lateinit var textViewKeyStatus: TextView
    private lateinit var btnGenerateKeys: Button
    private lateinit var btnExportPublicKey: Button
    private lateinit var editTextKeyName: EditText
    private lateinit var editTextPublicKey: EditText
    private lateinit var btnImportKey: Button
    private lateinit var recyclerViewKeys: RecyclerView

    private val pgpUtil = PGPUtil()
    private lateinit var keyManager: KeyManager
    private lateinit var keysAdapter: ImportedKeysAdapter

    companion object {
        var myPGPKeyPair: PGPUtil.PGPKeyPair? = null
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_settings)

        // Add back button to action bar
        supportActionBar?.setDisplayHomeAsUpEnabled(true)
        supportActionBar?.title = "Settings"

        keyManager = KeyManager(this)
        initializeViews()
        setupRecyclerView()
        setupClickListeners()
        updateKeyStatus()
    }

    override fun onSupportNavigateUp(): Boolean {
        finish()
        return true
    }

    private fun initializeViews() {
        textViewKeyStatus = findViewById(R.id.textViewKeyStatus)
        btnGenerateKeys = findViewById(R.id.btnGenerateKeys)
        btnExportPublicKey = findViewById(R.id.btnExportPublicKey)
        editTextKeyName = findViewById(R.id.editTextKeyName)
        editTextPublicKey = findViewById(R.id.editTextPublicKey)
        btnImportKey = findViewById(R.id.btnImportKey)
        recyclerViewKeys = findViewById(R.id.recyclerViewKeys)
    }

    private fun setupRecyclerView() {
        val importedKeys = keyManager.getImportedKeys().toMutableList()
        keysAdapter = ImportedKeysAdapter(importedKeys) { key ->
            keyManager.removeImportedKey(key.keyId)
            keysAdapter.removeKey(key)
            Toast.makeText(this, "Key '${key.name}' removed", Toast.LENGTH_SHORT).show()
        }

        recyclerViewKeys.layoutManager = LinearLayoutManager(this)
        recyclerViewKeys.adapter = keysAdapter
    }

    private fun setupClickListeners() {
        btnGenerateKeys.setOnClickListener {
            generatePGPKeys()
        }

        btnExportPublicKey.setOnClickListener {
            exportPublicKey()
        }

        btnImportKey.setOnClickListener {
            importPublicKey()
        }
    }

    private fun updateKeyStatus() {
        if (keyManager.hasMyKeys() && myPGPKeyPair != null) {
            textViewKeyStatus.text = "PGP keys generated and ready"
            btnExportPublicKey.isEnabled = true
        } else {
            textViewKeyStatus.text = "No PGP keys generated"
            btnExportPublicKey.isEnabled = false
        }
    }

    private fun generatePGPKeys() {
        // Show password dialog for key generation
        PasswordDialog.showPasswordDialog(
            this,
            "Create Password",
            "Enter a secure password to protect your PGP private key:",
            object : PasswordDialog.PasswordCallback {
                override fun onPasswordEntered(password: String) {
                    if (password.length < 4) {
                        Toast.makeText(this@SettingsActivity, "Password must be at least 4 characters long", Toast.LENGTH_SHORT).show()
                        return
                    }
                    performKeyGeneration(password)
                }

                override fun onPasswordCancelled() {
                    Toast.makeText(this@SettingsActivity, "Key generation cancelled", Toast.LENGTH_SHORT).show()
                }
            }
        )
    }

    private fun performKeyGeneration(password: String) {
        btnGenerateKeys.isEnabled = false
        textViewKeyStatus.text = "Generating keys..."

        CoroutineScope(Dispatchers.IO).launch {
            try {
                val identity = "EasyPGP User <user@easypgp.com>"
                myPGPKeyPair = pgpUtil.generateKeyPair(identity, password)

                // Save the generated key pair to persistent storage
                myPGPKeyPair?.let { keyPair ->
                    keyManager.saveMyKeyPair(keyPair)
                }

                keyManager.saveMyKeyStatus(true)

                withContext(Dispatchers.Main) {
                    textViewKeyStatus.text = "PGP keys generated and saved successfully!"
                    btnGenerateKeys.isEnabled = true
                    btnExportPublicKey.isEnabled = true

                    Toast.makeText(this@SettingsActivity, "Keys generated and saved! They will auto-load on next app start.", Toast.LENGTH_LONG).show()
                }
            } catch (e: Exception) {
                withContext(Dispatchers.Main) {
                    textViewKeyStatus.text = "Key generation failed: ${e.message}"
                    btnGenerateKeys.isEnabled = true
                    Toast.makeText(this@SettingsActivity, "Key generation failed: ${e.message}", Toast.LENGTH_LONG).show()
                }
            }
        }
    }

    private fun exportPublicKey() {
        myPGPKeyPair?.let { keyPair ->
            try {
                val publicKeyString = pgpUtil.getPublicKeyString(keyPair.publicKeyRing)

                // Copy to clipboard
                val clipboard = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
                val clip = ClipData.newPlainText("PGP Public Key", publicKeyString)
                clipboard.setPrimaryClip(clip)

                Toast.makeText(this, "Public key copied to clipboard!", Toast.LENGTH_SHORT).show()
            } catch (e: Exception) {
                Toast.makeText(this, "Failed to export public key: ${e.message}", Toast.LENGTH_LONG).show()
            }
        } ?: run {
            Toast.makeText(this, "No keys available to export", Toast.LENGTH_SHORT).show()
        }
    }

    private fun importPublicKey() {
        val keyName = editTextKeyName.text.toString().trim()
        val keyString = editTextPublicKey.text.toString().trim()

        if (keyName.isEmpty()) {
            Toast.makeText(this, "Please enter a name for this key", Toast.LENGTH_SHORT).show()
            return
        }

        if (keyString.isEmpty()) {
            Toast.makeText(this, "Please paste the public key", Toast.LENGTH_SHORT).show()
            return
        }

        if (!keyString.contains("-----BEGIN PGP PUBLIC KEY BLOCK-----")) {
            Toast.makeText(this, "Invalid PGP public key format", Toast.LENGTH_SHORT).show()
            return
        }

        try {
            // Parse and validate the public key
            val inputStream = ByteArrayInputStream(keyString.toByteArray())
            val decoderStream = org.bouncycastle.openpgp.PGPUtil.getDecoderStream(inputStream)
            val pgpObjectFactory = PGPObjectFactory(decoderStream, BcKeyFingerprintCalculator())

            val keyRing = pgpObjectFactory.nextObject() as PGPPublicKeyRing
            val publicKey = keyRing.publicKey
            val keyId = java.lang.Long.toHexString(publicKey.keyID).uppercase()

            // Save the key
            keyManager.saveImportedKey(keyName, keyString, keyId)

            // Add to adapter
            val importedKey = ImportedPublicKey(keyName, publicKey, keyId, keyString)
            keysAdapter.addKey(importedKey)

            // Clear input fields
            editTextKeyName.text.clear()
            editTextPublicKey.text.clear()

            Toast.makeText(this, "Public key for '$keyName' imported successfully!", Toast.LENGTH_SHORT).show()

        } catch (e: Exception) {
            Toast.makeText(this, "Failed to import key: ${e.message}", Toast.LENGTH_LONG).show()
        }
    }
}
