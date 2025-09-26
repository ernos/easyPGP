package com.yourdev.easypgp

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Intent
import android.os.Bundle
import android.view.inputmethod.InputMethodManager
import android.widget.*
import androidx.activity.enableEdgeToEdge
import androidx.appcompat.app.AppCompatActivity
import androidx.core.view.ViewCompat
import androidx.core.view.WindowInsetsCompat
import com.yourdev.easypgp.PGPUtil.PGPKeyPair
import com.yourdev.easypgp.PasswordDialog.Companion.showPasswordDialog
import com.yourdev.easypgp.PasswordDialog.PasswordCallback
import com.yourdev.easypgp.SettingsActivity.Companion.myPGPKeyPair
import kotlinx.coroutines.*
import org.bouncycastle.openpgp.PGPPublicKey
import org.bouncycastle.openpgp.operator.bc.BcPBESecretKeyDecryptorBuilder
import org.bouncycastle.openpgp.operator.bc.BcPGPDigestCalculatorProvider
import java.util.Date
import org.bouncycastle.openpgp.PGPSecretKeyRing
class MainActivity : AppCompatActivity() {
    private var keyringPassword: String = ""
    private var timestamp: Long = 0;
    private var timeoutValue: Long = 10000; // 30 seconds timeout
    private var keyringTimer: Job? = null

    private lateinit var btnSettings: Button
    private lateinit var spinnerRecipients: Spinner
    private lateinit var editTextInput: EditText
    private lateinit var btnEncrypt: Button
    private lateinit var btnDecrypt: Button
    private lateinit var btnUnlock: Button
    private lateinit var textViewOutput: TextView;
    private lateinit var textViewStatus: TextView;
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

        // Automatically load saved keys on startup
        loadSavedKeys()

        loadImportedKeys()

        // Start the keyring timer (but don't show unlock dialog automatically)
        startKeyringTimer()
    }

    private fun loadSavedKeys() {
        // Check if we have keys and what state they're in
        if (keyManager.hasMyKeys()) {
            // Try to load keys from storage
            val savedKeyPair = keyManager.loadMyKeyPair()
            if (savedKeyPair != null) {
                // Successfully loaded keys
                myPGPKeyPair = savedKeyPair

                if (keyManager.isKeyringLocked()) {
                    textViewStatus.text = "KEYS LOADED - LOCKED"
                    textViewStatus.setTextColor(getColorStateList(R.color.red))
                    Toast.makeText(this, "PGP keys loaded but locked - unlock to use", Toast.LENGTH_SHORT).show()
                } else {
                    textViewStatus.text = "KEYS LOADED - UNLOCKED"
                    textViewStatus.setTextColor(getColorStateList(R.color.green))
                    Toast.makeText(this, "PGP keys loaded successfully", Toast.LENGTH_SHORT).show()
                }
            } else {
                // Keys exist but couldn't be loaded (likely encrypted)
                textViewStatus.text = "KEYS ENCRYPTED - UNLOCK NEEDED"
                textViewStatus.setTextColor(getColorStateList(R.color.red))
                Toast.makeText(this, "Keys found but encrypted - use unlock button", Toast.LENGTH_SHORT).show()
            }
        } else {
            // No keys found at all
            textViewStatus.text = "NO KEYS - GENERATE IN SETTINGS"
            textViewStatus.setTextColor(getColorStateList(R.color.red))
            Toast.makeText(this, "No keys found - generate keys in Settings", Toast.LENGTH_SHORT).show()
        }
    }

    private fun startKeyringTimer() {
        timestamp = Date().time
        keyringTimer?.cancel() // Cancel any existing timer
        keyringTimer = CoroutineScope(Dispatchers.Main).launch {
            while(true) {
                val today = Date().time
                if(myPGPKeyPair?.secretKeyRing != null && keyringPassword.isNotEmpty()){
                    if(today > (timestamp + timeoutValue)){
                        // Only encrypt if keyring is currently unlocked
                        if (!keyManager.isKeyringLocked()) {
                            val privateKeyString = String(myPGPKeyPair?.secretKeyRing?.encoded ?: ByteArray(0))
                            try {
                                // Encrypt the private key
                                keyManager.encryptPrivateKeyAndStore(privateKeyString, keyringPassword)

                                // Remove the unencrypted version
                                keyManager.removeUnencryptedPrivateKey()

                                // Lock the keyring
                                keyManager.lockKeyring()
                            } catch (e: Exception) {
                                // Handle encryption error
                                Toast.makeText(this@MainActivity, "Failed to secure private key: ${e.message}", Toast.LENGTH_LONG).show()
                            }
                        }

                        // Clear password and update UI
                        keyringPassword = ""
                        keyManager.lockKeyring()
                        keyManager.clearEncryptionKey()
                        textViewStatus.text = "LOCKED"
                        textViewStatus.setTextColor(getColorStateList(R.color.red))
                        Toast.makeText(
                            this@MainActivity,
                            "Keyring locked due to inactivity",
                            Toast.LENGTH_SHORT
                        ).show()
                    }
                }
                delay(1000)
            }
        }
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
        btnUnlock = findViewById(R.id.btnUnlock)
        btnDecrypt = findViewById(R.id.btnDecrypt)
        textViewOutput = findViewById(R.id.textViewOutput)
        textViewStatus = findViewById(R.id.textViewStatus)
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

        btnUnlock.setOnClickListener {
            showUnlockDialog()
        }

        // Make output text copyable on tap - use manual copy with toast
        textViewOutput.setOnClickListener {
            manualCopyToClipboard()
        }
    }

    private fun showUnlockDialog() {
        showPasswordDialog(
            this,
            "Unlock Keyring",
            "Enter your PGP key password to unlock:",
            object : PasswordCallback {
                override fun onPasswordEntered(password: String) {
                    verifyPasswordAndUnlock(password)
                }

                override fun onPasswordCancelled() {
                    Toast.makeText(this@MainActivity, "Unlock cancelled", Toast.LENGTH_SHORT).show()
                }
            }
        )
    }

    private fun verifyPasswordAndUnlock(password: String) {
        CoroutineScope(Dispatchers.IO).launch {
            try {
                // Step 1: Get the key pair to test
                var keyPairToTest: PGPKeyPair? = null

                when {
                    // Case 1: Keys are already loaded in memory
                    myPGPKeyPair != null -> {
                        keyPairToTest = myPGPKeyPair
                    }
                    // Case 2: No keys in memory, try to load from storage
                    keyManager.hasMyKeys() -> {
                        // Try to load keys (handles both encrypted and unencrypted)
                        keyPairToTest = keyManager.loadMyKeyPair()
                        if (keyPairToTest == null && keyManager.isKeyringLocked()) {
                            // Keys are encrypted, try to decrypt them
                            val decryptedPrivateKeyString = keyManager.decryptStoredPrivateKey(null) // AES doesn't need PGP password
                            val publicKeyString = keyManager.getStoredPublicKey()

                            if (decryptedPrivateKeyString != null && publicKeyString != null) {
                                keyPairToTest = keyManager.reconstructKeyPairFromStrings(publicKeyString, decryptedPrivateKeyString)
                            }
                        }
                    }
                    else -> {
                        withContext(Dispatchers.Main) {
                            Toast.makeText(this@MainActivity, "No keys found - generate keys in Settings first", Toast.LENGTH_LONG).show()
                        }
                        return@launch
                    }
                }

                // Step 2: Verify the PGP password by testing encryption/decryption
                keyPairToTest?.let { keyPair ->
                    val testMessage = "Keyring unlock test message"

                    // Try to encrypt with public key
                    val encryptedText = pgpUtil.encrypt(testMessage, keyPair.publicKey)

                    // Try to decrypt with private key using provided password
                    val decryptor = BcPBESecretKeyDecryptorBuilder(
                        BcPGPDigestCalculatorProvider()
                    ).build(password.toCharArray())

                    val privateKey = keyPair.secretKeyRing.secretKey.extractPrivateKey(decryptor)
                    val decryptedText = pgpUtil.decrypt(encryptedText, privateKey)

                    // Step 3: Verify the password worked
                    if (decryptedText == testMessage) {
                        withContext(Dispatchers.Main) {
                            // Password is correct, update state
                            myPGPKeyPair = keyPair
                            keyringPassword = password
                            timestamp = Date().time

                            // Unlock the keyring
                            keyManager.unlockKeyring()

                            // Update UI
                            textViewStatus.text = "UNLOCKED"
                            textViewStatus.setTextColor(getColorStateList(R.color.green))

                            val timeRemaining = timeoutValue / 1000
                            Toast.makeText(this@MainActivity, "Keyring unlocked for $timeRemaining seconds!", Toast.LENGTH_SHORT).show()

                            // Start the timeout timer
                            startKeyringTimer()
                        }
                    } else {
                        withContext(Dispatchers.Main) {
                            Toast.makeText(this@MainActivity, "Unlock failed: verification failed", Toast.LENGTH_LONG).show()
                        }
                    }
                } ?: run {
                    withContext(Dispatchers.Main) {
                        Toast.makeText(this@MainActivity, "Could not load keys - may be corrupted", Toast.LENGTH_LONG).show()
                    }
                }
            } catch (e: Exception) {
                withContext(Dispatchers.Main) {
                    val errorMsg = if (e.message?.contains("checksum") == true || e.message?.contains("password") == true) {
                        "Incorrect password"
                    } else {
                        "Unlock failed: ${e.message}"
                    }
                    Toast.makeText(this@MainActivity, errorMsg, Toast.LENGTH_LONG).show()
                }
            }
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
                val clipboard = getSystemService(CLIPBOARD_SERVICE) as ClipboardManager
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
                val clipboard = getSystemService(CLIPBOARD_SERVICE) as ClipboardManager
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
        val inputMethodManager = getSystemService(INPUT_METHOD_SERVICE) as InputMethodManager
        currentFocus?.let { view ->
            inputMethodManager.hideSoftInputFromWindow(view.windowToken, 0)
        }
    }

    private fun loadImportedKeys() {
        importedKeys = keyManager.getImportedKeys()

        // Create spinner items with "My Key" option and imported keys
        val spinnerItems = mutableListOf<String>()
        spinnerItems.add("My Key (Self)")

        // Add all imported keys to the spinner
        for (importedKey in importedKeys) {
            spinnerItems.add(importedKey.name)
        }

        val adapter = ArrayAdapter(this, android.R.layout.simple_spinner_item, spinnerItems)
        adapter.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item)
        spinnerRecipients.adapter = adapter

        // Update output with instructions
        if (importedKeys.isEmpty()) {
            textViewOutput.text = "Go to Settings to:\n1. Generate your PGP keys\n2. Import public keys from others\n\nThen return here to encrypt/decrypt messages!"
        }
    }

    private fun updateButtonStates() {
        val hasMyKeys = keyManager.hasMyKeys() && myPGPKeyPair != null
        val hasImportedKeys = importedKeys.isNotEmpty()

        // Check if spinner has items and a selection before accessing selectedItem
        val selectedItem = spinnerRecipients.selectedItem?.toString()
        //if(hasImportedKeys && selectedItem != null && selectedItem != "My Key (Self)") {
            // Enable encrypt if we have imported keys (to encrypt for others)
            btnEncrypt.isEnabled = true
        //}

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
            myPGPKeyPair?.let { keyPair ->
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

    private fun encryptForKey(inputText: String, publicKey: PGPPublicKey, recipientName: String) {
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

        val keyPair = myPGPKeyPair
        if (keyPair == null) {
            Toast.makeText(this, "Please generate your keys in Settings first", Toast.LENGTH_SHORT).show()
            return
        }

        // If user opted to reuse password and keyring is unlocked, skip dialog
        if (!keyManager.isKeyringLocked() && keyManager.isUseSamePassword() && keyringPassword.isNotEmpty()) {
            performDecryption(inputText, keyPair, keyringPassword)
            return
        }

        // Otherwise, ask for password
        showPasswordDialog(
            this,
            "Enter Password",
            "Enter your PGP key password to decrypt the message:",
            object : PasswordCallback {
                override fun onPasswordEntered(password: String) {
                    performDecryption(inputText, keyPair, password)
                }

                override fun onPasswordCancelled() {
                    Toast.makeText(this@MainActivity, "Decryption cancelled", Toast.LENGTH_SHORT).show()
                }
            }
        )
    }

    private fun performDecryption(inputText: String, keyPair: PGPKeyPair, password: String) {
        btnDecrypt.isEnabled = false
        hideKeyboard()

        CoroutineScope(Dispatchers.IO).launch {
            try {
                // Re-extract private key with the provided password
                val decryptor = BcPBESecretKeyDecryptorBuilder(
                    BcPGPDigestCalculatorProvider()
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

    override fun onDestroy() {
        super.onDestroy()
        keyringTimer?.cancel() // Clean up timer when activity is destroyed
    }
}
