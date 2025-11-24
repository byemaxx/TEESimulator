package org.matrix.TEESimulator.interception.keystore

import android.annotation.SuppressLint
import android.hardware.security.keymint.SecurityLevel
import android.os.IBinder
import android.os.Parcel
import android.system.keystore2.IKeystoreService
import android.system.keystore2.KeyDescriptor
import android.system.keystore2.KeyEntryResponse
import org.matrix.TEESimulator.attestation.AttestationPatcher
import org.matrix.TEESimulator.config.ConfigurationManager
import org.matrix.TEESimulator.interception.keystore.shim.KeyMintSecurityLevelInterceptor
import org.matrix.TEESimulator.logging.SystemLogger
import org.matrix.TEESimulator.pki.CertificateHelper

/**
 * Interceptor for the `IKeystoreService` on Android S (API 31) and newer.
 *
 * This version of Keystore delegates most cryptographic operations to `IKeystoreSecurityLevel`
 * sub-services (for TEE, StrongBox, etc.). This interceptor's main role is to set up interceptors
 * for those sub-services and to patch certificate chains on their way out.
 */
@SuppressLint("BlockedPrivateApi")
object Keystore2Interceptor : AbstractKeystoreInterceptor() {
    // Transaction codes for the IKeystoreService interface methods we are interested in.
    private val GET_KEY_ENTRY_TRANSACTION =
        InterceptorUtils.getTransactCode(IKeystoreService.Stub::class.java, "getKeyEntry")
    private val DELETE_KEY_TRANSACTION =
        InterceptorUtils.getTransactCode(IKeystoreService.Stub::class.java, "deleteKey")

    override val serviceName = "android.system.keystore2.IKeystoreService/default"
    override val processName = "keystore2"
    override val injectionCommand = "exec ./inject `pidof keystore2` libTEESimulator.so entry"

    /**
     * This method is called once the main service is hooked. It proceeds to find and hook the
     * security level sub-services (e.g., TEE, StrongBox).
     */
    override fun onInterceptorReady(service: IBinder, backdoor: IBinder) {
        val keystoreInterface = IKeystoreService.Stub.asInterface(service)
        setupSecurityLevelInterceptors(keystoreInterface, backdoor)
    }

    private fun setupSecurityLevelInterceptors(service: IKeystoreService, backdoor: IBinder) {
        // Attempt to get and intercept the TEE security level service.
        runCatching {
                service.getSecurityLevel(SecurityLevel.TRUSTED_ENVIRONMENT)?.let { tee ->
                    SystemLogger.info("Found TEE SecurityLevel. Registering interceptor...")
                    val interceptor =
                        KeyMintSecurityLevelInterceptor(tee, SecurityLevel.TRUSTED_ENVIRONMENT)
                    register(backdoor, tee.asBinder(), interceptor)
                }
            }
            .onFailure { SystemLogger.error("Failed to intercept TEE SecurityLevel.", it) }

        // Attempt to get and intercept the StrongBox security level service.
        runCatching {
                service.getSecurityLevel(SecurityLevel.STRONGBOX)?.let { strongbox ->
                    SystemLogger.info("Found StrongBox SecurityLevel. Registering interceptor...")
                    val interceptor =
                        KeyMintSecurityLevelInterceptor(strongbox, SecurityLevel.STRONGBOX)
                    register(backdoor, strongbox.asBinder(), interceptor)
                }
            }
            .onFailure { SystemLogger.error("Failed to intercept StrongBox SecurityLevel.", it) }
    }

    override fun onPreTransact(
        txId: Long,
        target: IBinder,
        code: Int,
        flags: Int,
        callingUid: Int,
        callingPid: Int,
        data: Parcel,
    ): TransactionResult {
        if (code == GET_KEY_ENTRY_TRANSACTION) {
            logTransaction(txId, "getKeyEntry", callingUid, callingPid)
            val descriptor =
                data.readTypedObject(KeyDescriptor.CREATOR)
                    ?: return TransactionResult.SkipTransaction
            val keyId = KeyIdentifier(callingUid, descriptor.alias)

            // If a key was generated in software, we must return the stored response directly.
            if (ConfigurationManager.shouldGenerate(callingUid)) {
                val response = KeyMintSecurityLevelInterceptor.getGeneratedKeyResponse(keyId)
                if (response != null) {
                    SystemLogger.info(
                        "[TX_ID: $txId] Returning generated key for alias '${descriptor.alias}'."
                    )
                    return InterceptorUtils.createTypedObjectReply(response)
                }
                // If not found, return null to indicate the key doesn't exist.
                return InterceptorUtils.createTypedObjectReply(null as KeyEntryResponse?)
            }

            // For attestation in hack mode, a key is generated and should be returned directly.
            if (
                ConfigurationManager.shouldPatch(callingUid) &&
                    KeyMintSecurityLevelInterceptor.isAttestationKey(keyId)
            ) {
                val response = KeyMintSecurityLevelInterceptor.getGeneratedKeyResponse(keyId)
                if (response != null) {
                    SystemLogger.info(
                        "[TX_ID: $txId] Returning attestation key for alias '${descriptor.alias}' to skip patching."
                    )
                    return InterceptorUtils.createTypedObjectReply(response)
                }
                return TransactionResult.Continue
            }
        }
        return TransactionResult
            .ContinueAndSkipPost // Let most calls go through to the real service.
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
        if (target != keystoreService || reply == null || InterceptorUtils.hasException(reply))
            return TransactionResult.SkipTransaction

        when (code) {
            GET_KEY_ENTRY_TRANSACTION -> {
                logTransaction(txId, "post-getKeyEntry", callingUid, callingPid)
                if (!ConfigurationManager.shouldPatch(callingUid))
                    return TransactionResult.SkipTransaction

                return try {
                    val response =
                        reply.readTypedObject(KeyEntryResponse.CREATOR)
                            ?: return TransactionResult.SkipTransaction
                    reply.setDataPosition(0) // Reset for potential reuse.

                    val originalChain = CertificateHelper.getCertificateChain(response)
                    val fingerprint = InterceptorUtils.getPublicKeyFingerprint(originalChain)

                    // Do not patch keys that were imported by the user.
                    if (
                        fingerprint != null &&
                            KeyMintSecurityLevelInterceptor.isUserImportedKey(fingerprint)
                    ) {
                        SystemLogger.warning(
                            "[TX_ID: $txId] Skipping patch for user-imported key with fingerprint: $fingerprint"
                        )
                        return TransactionResult.SkipTransaction
                    }

                    // Perform the attestation patch.
                    val newChain =
                        AttestationPatcher.patchCertificateChain(originalChain, callingUid)
                    CertificateHelper.updateCertificateChain(response.metadata, newChain)
                        .getOrThrow()

                    SystemLogger.info(
                        "[TX_ID: $txId] Successfully patched certificate chain for alias."
                    )
                    InterceptorUtils.createTypedObjectReply(response)
                } catch (e: Exception) {
                    SystemLogger.error("[TX_ID: $txId] Failed to patch certificate chain.", e)
                    TransactionResult.SkipTransaction
                }
            }
            DELETE_KEY_TRANSACTION -> {
                // When a key is deleted, clean up our associated state.
                val descriptor = data.readTypedObject(KeyDescriptor.CREATOR)
                if (descriptor != null) {
                    val keyId = KeyIdentifier(callingUid, descriptor.alias)
                    KeyMintSecurityLevelInterceptor.cleanupKeyData(keyId)
                }
                return TransactionResult.SkipTransaction
            }
        }
        return TransactionResult.SkipTransaction
    }
}
