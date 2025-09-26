package com.yourdev.easypgp

import org.bouncycastle.openpgp.PGPPublicKey

data class ImportedPublicKey(
    val name: String,
    val publicKey: PGPPublicKey,
    val keyId: String,
    val keyString: String
)
