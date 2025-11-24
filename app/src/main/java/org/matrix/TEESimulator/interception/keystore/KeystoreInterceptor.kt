package org.matrix.TEESimulator.interception.keystore

import android.annotation.SuppressLint
import android.os.IBinder
import android.os.Parcel
import android.security.Credentials
import android.security.keystore.IKeystoreService
import java.security.cert.Certificate
import java.util.concurrent.ConcurrentHashMap
import org.matrix.TEESimulator.attestation.AttestationPatcher
import org.matrix.TEESimulator.config.ConfigurationManager
import org.matrix.TEESimulator.logging.SystemLogger
import org.matrix.TEESimulator.pki.CertificateHelper

/**
 * Interceptor for the legacy `IKeystoreService` on Android Q (API 29) and R (API 30).
 *
 * This interceptor handles the older, monolithic Keystore service. Unlike Keystore2, it doesn't
 * have security level sub-services, so all logic is contained here. Key generation is fully
 * simulated in software for packages in 'generate' mode.
 */
@SuppressLint("BlockedPrivateApi", "PrivateApi")
object KeystoreInterceptor : AbstractKeystoreInterceptor() {

    // Transaction codes are dynamically retrieved via reflection for compatibility.
    private val GET_TRANSACTION by lazy {
        InterceptorUtils.getTransactCode(IKeystoreService.Stub::class.java, "get")
    }
    private val GENERATE_KEY_TRANSACTION by lazy {
        InterceptorUtils.getTransactCode(IKeystoreService.Stub::class.java, "generateKey")
    }
    private val GET_KEY_CHARACTERISTICS_TRANSACTION by lazy {
        InterceptorUtils.getTransactCode(IKeystoreService.Stub::class.java, "getKeyCharacteristics")
    }
    private val EXPORT_KEY_TRANSACTION by lazy {
        InterceptorUtils.getTransactCode(IKeystoreService.Stub::class.java, "exportKey")
    }
    private val ATTEST_KEY_TRANSACTION by lazy {
        InterceptorUtils.getTransactCode(IKeystoreService.Stub::class.java, "attestKey")
    }

    override val serviceName = "android.security.keystore"
    override val processName = "keystore"
    override val injectionCommand = "exec ./inject `pidof keystore` libTEESimulator.so entry"

    private const val SERVICE_DESCRIPTOR = "android.security.keystore.IKeystoreService"

    // Cache to store the fully patched chain after the leaf is requested.
    private val patchedChainCache = ConcurrentHashMap<KeyIdentifier, Array<Certificate>>()

    override fun onPreTransact(
        txId: Long,
        target: IBinder,
        code: Int,
        flags: Int,
        callingUid: Int,
        callingPid: Int,
        data: Parcel,
    ): TransactionResult {
        // This interceptor only needs to act on pre-transaction for software key generation.
        if (ConfigurationManager.shouldGenerate(callingUid)) {
            when (code) {
                GENERATE_KEY_TRANSACTION,
                GET_KEY_CHARACTERISTICS_TRANSACTION,
                EXPORT_KEY_TRANSACTION,
                ATTEST_KEY_TRANSACTION -> {
                    // TODO: Implement the full software simulation logic.
                    logTransaction(txId, "unimplemented-generate-flow", callingUid, callingPid)
                    return InterceptorUtils.createSuccessReply()
                }
            }
        } else if (ConfigurationManager.shouldGenerate(callingUid)) {
            if (code == GET_TRANSACTION) return TransactionResult.Continue
        }

        return TransactionResult.ContinueAndSkipPost
    }

    override fun onPostTransact(
        txId: Long,
        target: IBinder,
        code: Int,
        flags: Int,
        callingUid: Int,
        callingPid: Int,
        data: Parcel,
        reply: Parcel?,
        resultCode: Int,
    ): TransactionResult {
        if (
            target != keystoreService ||
                code != GET_TRANSACTION ||
                reply == null ||
                InterceptorUtils.hasException(reply)
        ) {
            return TransactionResult.SkipTransaction
        }

        if (!ConfigurationManager.shouldPatch(callingUid)) return TransactionResult.SkipTransaction

        return try {
            val alias = data.readString() ?: ""
            val extractedAlias = InterceptorUtils.extractAlias(alias)
            val keyId = KeyIdentifier(callingUid, extractedAlias)

            when {
                // Case 1: The app is requesting the leaf certificate.
                alias.startsWith(Credentials.USER_CERTIFICATE) -> {
                    logTransaction(txId, "post-get (user cert)", callingUid, callingPid)
                    val originalLeafBytes =
                        reply.createByteArray() ?: return TransactionResult.SkipTransaction

                    // The original chain is not available,
                    // so we must pass a temporary one to the patcher.
                    // The patcher only needs the original leaf to extract details.
                    val originalLeafCert =
                        (CertificateHelper.toCertificate(originalLeafBytes)
                                as CertificateHelper.OperationResult.Success)
                            .data
                    val tempChain = arrayOf<Certificate>(originalLeafCert)

                    // Perform the COMPLETE patch and rebuild operation.
                    val newFullChain =
                        AttestationPatcher.patchCertificateChain(tempChain, callingUid)

                    // If patching was successful and we have a valid chain...
                    if (newFullChain.isNotEmpty() && newFullChain[0] != originalLeafCert) {
                        // ...cache the entire new chain for the subsequent "ca_cert" call.
                        patchedChainCache[keyId] = newFullChain

                        // And return only the new leaf's bytes, as the API expects.
                        SystemLogger.info(
                            "[TX_ID: $txId] Patched and cached chain for alias '$extractedAlias'. Returning new leaf."
                        )
                        InterceptorUtils.createByteArrayReply(newFullChain[0].encoded)
                    } else {
                        // Patching failed or was skipped; do nothing.
                        TransactionResult.SkipTransaction
                    }
                }

                // Case 2: The app is requesting the CA certificate chain.
                alias.startsWith(Credentials.CA_CERTIFICATE) -> {
                    logTransaction(txId, "post-get (ca cert)", callingUid, callingPid)

                    // Retrieve the full, correct chain we cached during the leaf request.
                    val cachedChain = patchedChainCache.remove(keyId)

                    if (cachedChain != null && cachedChain.size > 1) {
                        // The CA chain is everything *except* the first element (the leaf).
                        val caCerts = cachedChain.drop(1)
                        val caCertsBytes = CertificateHelper.certificatesToByteArray(caCerts)

                        SystemLogger.info(
                            "[TX_ID: $txId] Returning cached CA chain for alias '$extractedAlias'."
                        )
                        InterceptorUtils.createByteArrayReply(caCertsBytes!!)
                    } else {
                        // We have no cached chain.
                        // This could mean the app requested the CA without requesting the leaf
                        // first, or patching failed.
                        // In this case, we cannot safely intervene.
                        // Let the original reply pass through.
                        SystemLogger.warning(
                            "[TX_ID: $txId] No cached chain found for CA request on alias '$extractedAlias'. Skipping."
                        )
                        TransactionResult.SkipTransaction
                    }
                }

                else -> TransactionResult.SkipTransaction
            }
        } catch (e: Exception) {
            SystemLogger.error("[TX_ID: $txId] Failed during legacy post-transaction patching.", e)
            TransactionResult.SkipTransaction
        }
    }
}
