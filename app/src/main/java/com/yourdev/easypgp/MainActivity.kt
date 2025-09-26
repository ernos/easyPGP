package com.yourdev.easypgp

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.os.Bundle
import android.view.inputmethod.InputMethodManager
import android.widget.*
import androidx.activity.enableEdgeToEdge
import androidx.appcompat.app.AppCompatActivity
import androidx.core.view.ViewCompat
import androidx.core.view.WindowInsetsCompat
import kotlinx.coroutines.*

class MainActivity : AppCompatActivity() {

    private lateinit var btnSettings: Button
    private lateinit var spinnerRecipients: Spinner
    private lateinit var editTextInput: EditText
    private lateinit var btnEncrypt: Button
    private lateinit var btnDecrypt: Button
    private lateinit var textViewOutput: TextView

    private val pgpUtil = PGPUtil()
    private lateinit var keyManager: KeyManager
    private var importedKeys: List<ImportedPublicKey> = emptyList()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        setContentView(R.layout.activity_main)
        ViewCompat.setOnApplyWindowInsetsListener(findViewById(R.id.main)) { v, insets ->
            val systemBars = insets.getInsets(WindowInsetsCompat.Type.systemBars())
            v.setPadding(systemBars.left, systemBars.top, systemBars.right, systemBars.bottom)
            insets
        }

        keyManager = KeyManager(this)
        initializeViews()
        setupClickListeners()
        loadImportedKeys()
    }

    override fun onResume() {
        super.onResume()
        loadImportedKeys()
        updateButtonStates()
    }

    private fun initializeViews() {
        btnSettings = findViewById(R.id.btnSettings)
        spinnerRecipients = findViewById(R.id.spinnerRecipients)
        editTextInput = findViewById(R.id.editTextInput)
        btnEncrypt = findViewById(R.id.btnEncrypt)
        btnDecrypt = findViewById(R.id.btnDecrypt)
        textViewOutput = findViewById(R.id.textViewOutput)
    }

    private fun setupClickListeners() {
        btnSettings.setOnClickListener {
            startActivity(Intent(this, SettingsActivity::class.java))
        }

        btnEncrypt.setOnClickListener {
            encryptText()
        }

        btnDecrypt.setOnClickListener {
            decryptText()
        }

        // Make output text copyable on tap - use manual copy with toast
        textViewOutput.setOnClickListener {
            manualCopyToClipboard()
        }
    }

    private fun copyOutputToClipboard() {
        val outputText = textViewOutput.text.toString()

        // Check if the content is valid for copying
        val isValidContent = outputText.isNotEmpty() &&
                outputText != "Output will appear here" &&
                !outputText.startsWith("Go to Settings") &&
                !outputText.startsWith("Generate your keys") &&
                !outputText.startsWith("Import others'") &&
                !outputText.contains("failed:") &&
                !outputText.contains("Encryption failed") &&
                !outputText.contains("Decryption failed") &&
                !outputText.contains("error")

        if (isValidContent) {
            try {
                val clipboard = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
                val clip = ClipData.newPlainText("PGP Output", outputText)
                clipboard.setPrimaryClip(clip)

                // Don't show toast here when called from auto-copy, as the main operation already shows a toast
                // Only show toast when manually tapping the output area
            } catch (e: Exception) {
                Toast.makeText(this, "Failed to copy to clipboard: ${e.message}", Toast.LENGTH_SHORT).show()
            }
        }
    }

    // Separate function for manual copy (when user taps output)
    private fun manualCopyToClipboard() {
        val outputText = textViewOutput.text.toString()

        val isValidContent = outputText.isNotEmpty() &&
                outputText != "Output will appear here" &&
                !outputText.startsWith("Go to Settings") &&
                !outputText.startsWith("Generate your keys") &&
                !outputText.startsWith("Import others'") &&
                !outputText.contains("failed:") &&
                !outputText.contains("Encryption failed") &&
                !outputText.contains("Decryption failed") &&
                !outputText.contains("error")

        if (isValidContent) {
            try {
                val clipboard = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
                val clip = ClipData.newPlainText("PGP Output", outputText)
                clipboard.setPrimaryClip(clip)

                Toast.makeText(this, "Content copied to clipboard!", Toast.LENGTH_SHORT).show()
            } catch (e: Exception) {
                Toast.makeText(this, "Failed to copy to clipboard: ${e.message}", Toast.LENGTH_SHORT).show()
            }
        } else {
            Toast.makeText(this, "No content to copy", Toast.LENGTH_SHORT).show()
        }
    }

    private fun hideKeyboard() {
        val inputMethodManager = getSystemService(Context.INPUT_METHOD_SERVICE) as InputMethodManager
        currentFocus?.let { view ->
            inputMethodManager.hideSoftInputFromWindow(view.windowToken, 0)
        }
    }

    private fun loadImportedKeys() {
        importedKeys = keyManager.getImportedKeys()

        // Create spinner items with "My Key" option and imported keys
        val spinnerItems = mutableListOf<String>()
        spinnerItems.add("My Key (Self)")
        spinnerItems.addAll(importedKeys.map { it.name })

        val adapter = ArrayAdapter(this, android.R.layout.simple_spinner_item, spinnerItems)
        adapter.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item)
        spinnerRecipients.adapter = adapter

        // Update output with instructions
        if (importedKeys.isEmpty()) {
            textViewOutput.text = "Go to Settings to:\n1. Generate your PGP keys\n2. Import public keys from others\n\nThen return here to encrypt/decrypt messages!"
        }
    }

    private fun updateButtonStates() {
        val hasMyKeys = keyManager.hasMyKeys() && SettingsActivity.myPGPKeyPair != null
        val hasImportedKeys = importedKeys.isNotEmpty()

        if(hasImportedKeys && spinnerRecipients.selectedItem.toString() != "My Key (Self)")
        // Enable encrypt if we have imported keys (to encrypt for others)
            btnEncrypt.isEnabled = true

            // If only "My Key"
        // Enable decrypt if we have our own keys (to decrypt messages sent to us)
        btnDecrypt.isEnabled = hasMyKeys

        if (!hasMyKeys && !hasImportedKeys) {
            textViewOutput.text = "Go to Settings to generate your keys and import others' public keys first."
        } else if (!hasMyKeys) {
            textViewOutput.text = "Generate your keys in Settings to decrypt messages sent to you."
        } else if (!hasImportedKeys) {
            textViewOutput.text = "Import others' public keys in Settings to encrypt messages for them."
        }
    }

    private fun encryptText() {
        val inputText = editTextInput.text.toString()
        if (inputText.isEmpty()) {
            Toast.makeText(this, "Please enter text to encrypt", Toast.LENGTH_SHORT).show()
            return
        }

        val selectedPosition = spinnerRecipients.selectedItemPosition

        if (selectedPosition == 0) {
            // "My Key" selected - encrypt for ourselves
            SettingsActivity.myPGPKeyPair?.let { keyPair ->
                encryptForKey(inputText, keyPair.publicKey, "yourself")
            } ?: run {
                Toast.makeText(this, "Please generate your keys in Settings first", Toast.LENGTH_SHORT).show()
            }
        } else {
            // Imported key selected
            val selectedKey = importedKeys.getOrNull(selectedPosition - 1)
            if (selectedKey != null) {
                encryptForKey(inputText, selectedKey.publicKey, selectedKey.name)
            } else {
                Toast.makeText(this, "Please select a valid recipient", Toast.LENGTH_SHORT).show()
            }
        }
    }

    private fun encryptForKey(inputText: String, publicKey: org.bouncycastle.openpgp.PGPPublicKey, recipientName: String) {
        btnEncrypt.isEnabled = false
        hideKeyboard()

        CoroutineScope(Dispatchers.IO).launch {
            try {
                val encryptedText = pgpUtil.encrypt(inputText, publicKey)

                withContext(Dispatchers.Main) {
                    // Clean output - just show the encrypted text without prefix
                    textViewOutput.text = encryptedText
                    btnEncrypt.isEnabled = true

                    // Auto-copy to clipboard after successful encryption
                    copyOutputToClipboard()

                    Toast.makeText(this@MainActivity, "Text encrypted for $recipientName and copied to clipboard!", Toast.LENGTH_SHORT).show()
                }
            } catch (e: Exception) {
                withContext(Dispatchers.Main) {
                    textViewOutput.text = "Encryption failed: ${e.message}"
                    btnEncrypt.isEnabled = true
                    Toast.makeText(this@MainActivity, "Encryption failed: ${e.message}", Toast.LENGTH_LONG).show()
                }
            }
        }
    }

    private fun decryptText() {
        val inputText = editTextInput.text.toString()
        if (inputText.isEmpty()) {
            Toast.makeText(this, "Please enter encrypted text to decrypt", Toast.LENGTH_SHORT).show()
            return
        }

        SettingsActivity.myPGPKeyPair?.let { keyPair ->
            // Show password dialog for decryption
            PasswordDialog.showPasswordDialog(
                this,
                "Enter Password",
                "Enter your PGP key password to decrypt the message:",
                object : PasswordDialog.PasswordCallback {
                    override fun onPasswordEntered(password: String) {
                        performDecryption(inputText, keyPair, password)
                    }

                    override fun onPasswordCancelled() {
                        Toast.makeText(this@MainActivity, "Decryption cancelled", Toast.LENGTH_SHORT).show()
                    }
                }
            )
        } ?: run {
            Toast.makeText(this, "Please generate your keys in Settings first", Toast.LENGTH_SHORT).show()
        }
    }

    private fun performDecryption(inputText: String, keyPair: PGPUtil.PGPKeyPair, password: String) {
        btnDecrypt.isEnabled = false
        hideKeyboard()

        CoroutineScope(Dispatchers.IO).launch {
            try {
                // Re-extract private key with the provided password
                val decryptor = org.bouncycastle.openpgp.operator.bc.BcPBESecretKeyDecryptorBuilder(
                    org.bouncycastle.openpgp.operator.bc.BcPGPDigestCalculatorProvider()
                ).build(password.toCharArray())

                val privateKey = keyPair.secretKeyRing.secretKey.extractPrivateKey(decryptor)
                val decryptedText = pgpUtil.decrypt(inputText, privateKey)

                withContext(Dispatchers.Main) {
                    textViewOutput.text = decryptedText
                    btnDecrypt.isEnabled = true

                    // Auto-copy to clipboard after successful decryption
                    copyOutputToClipboard()

                    Toast.makeText(this@MainActivity, "Message decrypted and copied to clipboard!", Toast.LENGTH_SHORT).show()
                }
            } catch (e: Exception) {
                withContext(Dispatchers.Main) {
                    val errorMsg = if (e.message?.contains("checksum") == true || e.message?.contains("password") == true) {
                        "Incorrect password or corrupted key"
                    } else {
                        "Decryption failed: ${e.message}"
                    }
                    textViewOutput.text = errorMsg
                    btnDecrypt.isEnabled = true
                    Toast.makeText(this@MainActivity, errorMsg, Toast.LENGTH_LONG).show()
                }
            }
        }
    }
}