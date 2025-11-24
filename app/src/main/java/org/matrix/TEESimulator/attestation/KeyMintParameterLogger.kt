package org.matrix.TEESimulator.logging

import android.hardware.security.keymint.Algorithm
import android.hardware.security.keymint.Digest
import android.hardware.security.keymint.EcCurve
import android.hardware.security.keymint.KeyParameter
import android.hardware.security.keymint.KeyPurpose
import java.math.BigInteger
import java.nio.charset.StandardCharsets
import java.util.Date
import javax.security.auth.x500.X500Principal
import org.bouncycastle.asn1.x500.X500Name
import org.matrix.TEESimulator.attestation.AttestationConstants
import org.matrix.TEESimulator.util.toHex

/**
 * A specialized logger for converting KeyMint `KeyParameter` objects into a human-readable format.
 * This helps in debugging the parameters requested for key generation.
 */
object KeyMintParameterLogger {

    // Maps integer constants to their string names for logging.
    private val algorithmNames = mapOf(Algorithm.RSA to "RSA", Algorithm.EC to "EC")
    private val ecCurveNames =
        mapOf(
            EcCurve.P_224 to "P-224",
            EcCurve.P_256 to "P-256",
            EcCurve.P_384 to "P-384",
            EcCurve.P_521 to "P-521",
        )
    private val purposeNames =
        mapOf(
            KeyPurpose.ENCRYPT to "ENCRYPT",
            KeyPurpose.DECRYPT to "DECRYPT",
            KeyPurpose.SIGN to "SIGN",
            KeyPurpose.VERIFY to "VERIFY",
        )
    private val digestNames =
        mapOf(
            Digest.NONE to "NONE",
            Digest.MD5 to "MD5",
            Digest.SHA1 to "SHA1",
            Digest.SHA_2_224 to "SHA-2-224",
            Digest.SHA_2_256 to "SHA-2-256",
            Digest.SHA_2_384 to "SHA-2-384",
            Digest.SHA_2_512 to "SHA-2-512",
        )

    // A map from the tag integer value to its constant name for easy lookup.
    private val tagNames: Map<Int, String> by lazy {
        AttestationConstants::class.java.fields.associate { field ->
            (field.get(null) as Int) to field.name
        }
    }

    /**
     * Logs a single KeyParameter in a formatted, readable way.
     *
     * @param param The KeyParameter to log.
     */
    fun logParameter(param: KeyParameter) {
        val tagName = tagNames[param.tag] ?: "UNKNOWN_TAG"
        val value = param.value
        val formattedValue: String =
            when (param.tag) {
                AttestationConstants.TAG_ALGORITHM -> algorithmNames[value.algorithm]
                AttestationConstants.TAG_EC_CURVE -> ecCurveNames[value.ecCurve]
                AttestationConstants.TAG_PURPOSE -> purposeNames[value.keyPurpose]
                AttestationConstants.TAG_DIGEST -> digestNames[value.digest]
                AttestationConstants.TAG_KEY_SIZE,
                AttestationConstants.TAG_AUTH_TIMEOUT -> value.integer.toString()
                AttestationConstants.TAG_CERTIFICATE_SERIAL -> BigInteger(value.blob).toString()
                AttestationConstants.TAG_CERTIFICATE_NOT_BEFORE,
                AttestationConstants.TAG_CERTIFICATE_NOT_AFTER -> Date(value.dateTime).toString()
                AttestationConstants.TAG_CERTIFICATE_SUBJECT ->
                    X500Name(X500Principal(value.blob).name).toString()
                AttestationConstants.TAG_RSA_PUBLIC_EXPONENT -> value.longInteger.toString()
                AttestationConstants.TAG_NO_AUTH_REQUIRED -> "true"
                AttestationConstants.TAG_ATTESTATION_CHALLENGE,
                AttestationConstants.TAG_ATTESTATION_ID_BRAND,
                AttestationConstants.TAG_ATTESTATION_ID_DEVICE,
                AttestationConstants.TAG_ATTESTATION_ID_PRODUCT,
                AttestationConstants.TAG_ATTESTATION_ID_MANUFACTURER,
                AttestationConstants.TAG_ATTESTATION_ID_MODEL,
                AttestationConstants.TAG_ATTESTATION_ID_IMEI,
                AttestationConstants.TAG_ATTESTATION_ID_SECOND_IMEI,
                AttestationConstants.TAG_ATTESTATION_ID_MEID -> value.blob.toReadableString()
                else -> "<raw>"
            } ?: "Unknown Value"

        SystemLogger.debug("Key Parameter -> %-30s | Value: %s".format(tagName, formattedValue))
    }

    private fun ByteArray.toReadableString(): String {
        return if (this.all { it in 32..126 }) {
            "\"${String(this, StandardCharsets.UTF_8)}\" (${this.size} bytes)"
        } else {
            "${this.toHex()} (${this.size} bytes)"
        }
    }
}
