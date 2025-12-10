package com.yourdev.easypgp

import android.widget.Toast
import org.bouncycastle.bcpg.ArmoredOutputStream
import org.bouncycastle.bcpg.HashAlgorithmTags
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.openpgp.*
import org.bouncycastle.openpgp.operator.PBESecretKeyEncryptor
import org.bouncycastle.openpgp.operator.PGPDigestCalculator
import org.bouncycastle.openpgp.operator.bc.*
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPKeyPair
import java.io.*
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.SecureRandom
import java.security.Security
import java.util.*

class PGPUtil {

    init {
        // Add BouncyCastle as security provider
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(BouncyCastleProvider())
        }
    }

    data class PGPKeyPair(
        val publicKey: PGPPublicKey,
        val publicKeyRing: PGPPublicKeyRing,
        val secretKeyRing: PGPSecretKeyRing
    )

    fun generateKeyPair(identity: String, passphrase: String): PGPKeyPair {
        val keyPairGenerator = KeyPairGenerator.getInstance("RSA", BouncyCastleProvider.PROVIDER_NAME)
        keyPairGenerator.initialize(2048)
        val keyPair: KeyPair = keyPairGenerator.generateKeyPair()

        val digestCalculator: PGPDigestCalculator = BcPGPDigestCalculatorProvider()
            .get(HashAlgorithmTags.SHA1)

        val keyEncryptor: PBESecretKeyEncryptor = BcPBESecretKeyEncryptorBuilder(
            SymmetricKeyAlgorithmTags.AES_256, digestCalculator, 0x60
        ).build(passphrase.toCharArray())

        // Convert Java KeyPair to PGPKeyPair using JCA adapter
        val pgpKeyPair = JcaPGPKeyPair(PublicKeyAlgorithmTags.RSA_GENERAL, keyPair, Date())

        val keyRingGenerator = PGPKeyRingGenerator(
            PGPSignature.POSITIVE_CERTIFICATION,
            pgpKeyPair,
            identity,
            digestCalculator,
            null,
            null,
            BcPGPContentSignerBuilder(PublicKeyAlgorithmTags.RSA_GENERAL, HashAlgorithmTags.SHA1),
            keyEncryptor
        )

        val publicKeyRing = keyRingGenerator.generatePublicKeyRing()
        val secretKeyRing = keyRingGenerator.generateSecretKeyRing()

        val publicKey = publicKeyRing.publicKey

        // Return key pair WITHOUT storing the decrypted private key
        return PGPKeyPair(publicKey, publicKeyRing, secretKeyRing)
    }

    fun encrypt(plainText: String, publicKey: PGPPublicKey): String {
        val byteArrayOutputStream = ByteArrayOutputStream()
        val armoredOutputStream = ArmoredOutputStream(byteArrayOutputStream)

        val encryptedDataGenerator = PGPEncryptedDataGenerator(
            BcPGPDataEncryptorBuilder(SymmetricKeyAlgorithmTags.AES_256)
                .setWithIntegrityPacket(true)
                .setSecureRandom(SecureRandom())
        )

        encryptedDataGenerator.addMethod(BcPublicKeyKeyEncryptionMethodGenerator(publicKey))

        val encryptedOut = encryptedDataGenerator.open(armoredOutputStream, ByteArray(1024))

        val compressedDataGenerator = PGPCompressedDataGenerator(PGPCompressedData.ZIP)
        val compressedOut = compressedDataGenerator.open(encryptedOut)

        val literalDataGenerator = PGPLiteralDataGenerator()
        val literalOut = literalDataGenerator.open(
            compressedOut,
            PGPLiteralData.BINARY,
            PGPLiteralData.CONSOLE,
            plainText.toByteArray().size.toLong(),
            Date()
        )

        literalOut.write(plainText.toByteArray())
        literalOut.close()
        compressedOut.close()
        encryptedOut.close()
        armoredOutputStream.close()

        return byteArrayOutputStream.toString()
    }

    fun decrypt(encryptedText: String, privateKey: PGPPrivateKey): String {
        try {
            // Validate input text format
            val trimmedText = encryptedText.trim()
            if (!trimmedText.contains("-----BEGIN PGP MESSAGE-----")) {
                throw IllegalArgumentException("Invalid PGP message format - must contain PGP MESSAGE block")
            }

            val inputStream = ByteArrayInputStream(trimmedText.toByteArray())
            val decoderStream = org.bouncycastle.openpgp.PGPUtil.getDecoderStream(inputStream)
            val pgpObjectFactory = PGPObjectFactory(decoderStream, BcKeyFingerprintCalculator())

            // Find the encrypted data list by iterating through objects
            var encryptedDataList: PGPEncryptedDataList? = null
            var obj = pgpObjectFactory.nextObject()

            while (obj != null && encryptedDataList == null) {
                when (obj) {
                    is PGPEncryptedDataList -> {
                        encryptedDataList = obj
                    }
                    else -> {
                        obj = pgpObjectFactory.nextObject()
                    }
                }
            }

            if (encryptedDataList == null) {
                throw IllegalArgumentException("No encrypted data found - message may be corrupted or not a valid PGP message")
            }

            // Find the correct encrypted data packet that matches our key
            var encryptedData: PGPPublicKeyEncryptedData? = null
            val keyId = privateKey.keyID
            val iterator = encryptedDataList.encryptedDataObjects
            var foundCompatiblePacket = false

            while (iterator.hasNext()) {
                val encData = iterator.next()
                if (encData is PGPPublicKeyEncryptedData) {
                    foundCompatiblePacket = true
                    // Check if this packet is encrypted for our key
                    if (encData.keyID == keyId || encData.keyID == 0L) {
                        encryptedData = encData
                        break
                    }
                }
            }

            if (!foundCompatiblePacket) {
                throw IllegalArgumentException("No public key encrypted packets found in message")
            }

            if (encryptedData == null) {
                throw IllegalArgumentException("Message was not encrypted for your key - cannot decrypt")
            }

            val dataStream = try {
                encryptedData.getDataStream(BcPublicKeyDataDecryptorFactory(privateKey))
            } catch (e: Exception) {
                when {
                    e.message?.contains("checksum") == true ->
                        throw IllegalArgumentException("Incorrect password - checksum mismatch")
                    e.message?.contains("block") == true ->
                        throw IllegalArgumentException("Decryption block error - wrong key or corrupted data")
                    e.message?.contains("padding") == true ->
                        throw IllegalArgumentException("Padding error - message may be corrupted")
                    else ->
                        throw IllegalArgumentException("Failed to decrypt data stream: ${e.message}")
                }
            }

            val plainObjectFactory = PGPObjectFactory(dataStream, BcKeyFingerprintCalculator())
            val compressedData = plainObjectFactory.nextObject() as? PGPCompressedData
                ?: throw IllegalArgumentException("Expected compressed data not found - message structure invalid")

            val compressedObjectFactory = PGPObjectFactory(
                compressedData.dataStream,
                BcKeyFingerprintCalculator()
            )
            val literalData = compressedObjectFactory.nextObject() as? PGPLiteralData
                ?: throw IllegalArgumentException("Expected literal data not found - message structure invalid")

            val literalDataStream = literalData.inputStream
            val decryptedBytes = literalDataStream.readBytes()

            if (decryptedBytes.isEmpty()) {
                throw IllegalArgumentException("Decrypted data is empty - message may be corrupted")
            }

            return String(decryptedBytes, Charsets.UTF_8)

        } catch (e: IllegalArgumentException) {
            throw e // Re-throw our custom messages
        } catch (e: Exception) {
            // Handle other unexpected errors
            val errorMsg = when {
                e.message?.contains("IOException") == true -> "Failed to read PGP message - format may be corrupted"
                e.message?.contains("EOFException") == true -> "Incomplete PGP message - data appears truncated"
                e.message?.contains("NoSuchAlgorithmException") == true -> "Unsupported encryption algorithm"
                else -> "Unexpected decryption error: ${e.message}"
            }
            throw Exception(errorMsg, e)
        }
    }


    fun getPublicKeyString(publicKeyRing: PGPPublicKeyRing): String {
        val byteArrayOutputStream = ByteArrayOutputStream()
        val armoredOutputStream = ArmoredOutputStream(byteArrayOutputStream)
        publicKeyRing.encode(armoredOutputStream)
        armoredOutputStream.close()
        return byteArrayOutputStream.toString()
    }

    fun getPrivateKeyString(secretKeyRing: PGPSecretKeyRing): String {
        val byteArrayOutputStream = ByteArrayOutputStream()
        val armoredOutputStream = ArmoredOutputStream(byteArrayOutputStream)
        secretKeyRing.encode(armoredOutputStream)
        armoredOutputStream.close()
        return byteArrayOutputStream.toString()
    }
}
