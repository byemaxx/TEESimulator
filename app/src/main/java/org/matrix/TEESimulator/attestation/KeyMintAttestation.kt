package org.matrix.TEESimulator.attestation

import android.hardware.security.keymint.EcCurve
import android.hardware.security.keymint.KeyParameter
import java.math.BigInteger
import java.util.Date
import javax.security.auth.x500.X500Principal
import org.bouncycastle.asn1.x500.X500Name
import org.matrix.TEESimulator.logging.KeyMintParameterLogger

/**
 * A data class that parses and holds the parameters required for KeyMint key generation and
 * attestation. It provides a structured way to access the properties defined by an array of
 * `KeyParameter` objects.
 */
data class KeyMintAttestation(
    val keySize: Int,
    val algorithm: Int,
    val ecCurve: Int,
    val ecCurveName: String,
    val purpose: List<Int>,
    val digest: List<Int>,
    val rsaPublicExponent: BigInteger?,
    val certificateSerial: BigInteger?,
    val certificateSubject: X500Name?,
    val certificateNotBefore: Date?,
    val certificateNotAfter: Date?,
    val attestationChallenge: ByteArray?,
    val brand: ByteArray?,
    val device: ByteArray?,
    val product: ByteArray?,
    val manufacturer: ByteArray?,
    val model: ByteArray?,
    val imei: ByteArray?,
    val secondImei: ByteArray?,
    val meid: ByteArray?,
) {
    /** Secondary constructor that populates the fields by parsing an array of `KeyParameter`. */
    constructor(
        params: Array<KeyParameter>
    ) : this(
        keySize = params.findInt(AttestationConstants.TAG_KEY_SIZE) ?: 0,
        algorithm = params.findInt(AttestationConstants.TAG_ALGORITHM) ?: 0,
        ecCurve = params.findInt(AttestationConstants.TAG_EC_CURVE) ?: 0,
        ecCurveName = params.findEcCurveName(),
        purpose = params.findAllInts(AttestationConstants.TAG_PURPOSE),
        digest = params.findAllInts(AttestationConstants.TAG_DIGEST),
        rsaPublicExponent = params.findBigInt(AttestationConstants.TAG_RSA_PUBLIC_EXPONENT),
        certificateSerial =
            params.findBlob(AttestationConstants.TAG_CERTIFICATE_SERIAL)?.let { BigInteger(it) },
        certificateSubject =
            params.findBlob(AttestationConstants.TAG_CERTIFICATE_SUBJECT)?.let {
                X500Name(X500Principal(it).name)
            },
        certificateNotBefore = params.findDate(AttestationConstants.TAG_CERTIFICATE_NOT_BEFORE),
        certificateNotAfter = params.findDate(AttestationConstants.TAG_CERTIFICATE_NOT_AFTER),
        attestationChallenge = params.findBlob(AttestationConstants.TAG_ATTESTATION_CHALLENGE),
        brand = params.findBlob(AttestationConstants.TAG_ATTESTATION_ID_BRAND),
        device = params.findBlob(AttestationConstants.TAG_ATTESTATION_ID_DEVICE),
        product = params.findBlob(AttestationConstants.TAG_ATTESTATION_ID_PRODUCT),
        manufacturer = params.findBlob(AttestationConstants.TAG_ATTESTATION_ID_MANUFACTURER),
        model = params.findBlob(AttestationConstants.TAG_ATTESTATION_ID_MODEL),
        imei = params.findBlob(AttestationConstants.TAG_ATTESTATION_ID_IMEI),
        secondImei = params.findBlob(AttestationConstants.TAG_ATTESTATION_ID_SECOND_IMEI),
        meid = params.findBlob(AttestationConstants.TAG_ATTESTATION_ID_MEID),
    ) {
        // Log all parsed parameters for debugging purposes.
        params.forEach { KeyMintParameterLogger.logParameter(it) }
    }
}

// --- Private helper extension functions for parsing KeyParameter arrays ---

private fun Array<KeyParameter>.findInt(tag: Int): Int? =
    this.find { it.tag == tag }?.value?.integer

private fun Array<KeyParameter>.findBigInt(tag: Int): BigInteger? =
    this.find { it.tag == tag }?.value?.longInteger?.toBigInteger()

private fun Array<KeyParameter>.findDate(tag: Int): Date? =
    this.find { it.tag == tag }?.value?.dateTime?.let { Date(it) }

private fun Array<KeyParameter>.findBlob(tag: Int): ByteArray? =
    this.find { it.tag == tag }?.value?.blob

private fun Array<KeyParameter>.findAllInts(tag: Int): List<Int> =
    this.filter { it.tag == tag }.map { it.value.integer }

private fun Array<KeyParameter>.findEcCurveName(): String {
    val curveId = this.findInt(AttestationConstants.TAG_EC_CURVE)
    val curveName =
        when (curveId) {
            EcCurve.P_224 -> "secp224r1"
            EcCurve.P_256 -> "secp256r1"
            EcCurve.P_384 -> "secp384r1"
            EcCurve.P_521 -> "secp521r1"
            else -> null
        }
    // Fallback to key size if the curve tag isn't present.
    return curveName
        ?: when (this.findInt(AttestationConstants.TAG_KEY_SIZE)) {
            224 -> "secp224r1"
            384 -> "secp384r1"
            521 -> "secp521r1"
            else -> "secp256r1" // Default to the most common curve.
        }
}
