/*
 * Copyright 2025 Dakkshesh <beakthoven@gmail.com>
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

package io.github.beakthoven.TrickyStoreOSS.interceptors

import android.annotation.SuppressLint
import android.hardware.security.keymint.SecurityLevel
import android.os.IBinder
import android.os.Parcel
import android.system.keystore2.IKeystoreService
import android.system.keystore2.KeyDescriptor
import android.system.keystore2.KeyEntryResponse
import io.github.beakthoven.TrickyStoreOSS.CertificateHack
import io.github.beakthoven.TrickyStoreOSS.CertificateUtils
import io.github.beakthoven.TrickyStoreOSS.KeyBoxUtils
import io.github.beakthoven.TrickyStoreOSS.config.PkgConfig
import io.github.beakthoven.TrickyStoreOSS.interceptors.InterceptorUtils.createTypedObjectReply
import io.github.beakthoven.TrickyStoreOSS.interceptors.InterceptorUtils.getTransactCode
import io.github.beakthoven.TrickyStoreOSS.interceptors.InterceptorUtils.hasException
import io.github.beakthoven.TrickyStoreOSS.logging.Logger
import io.github.beakthoven.TrickyStoreOSS.putCertificateChain

@SuppressLint("BlockedPrivateApi")
object Keystore2Interceptor : BaseKeystoreInterceptor() {
    private val getSecurityLevelTransaction =
        getTransactCode(IKeystoreService.Stub::class.java, "getSecurityLevel")
    private val getKeyEntryTransaction =
        getTransactCode(IKeystoreService.Stub::class.java, "getKeyEntry")
    private val updateSubcomponentTransaction =
        getTransactCode(IKeystoreService.Stub::class.java, "updateSubcomponent")
    private val listEntriesTransaction =
        getTransactCode(IKeystoreService.Stub::class.java, "listEntries")
    private val deleteKeyTransaction =
        getTransactCode(IKeystoreService.Stub::class.java, "deleteKey")
    private val grantTransaction = getTransactCode(IKeystoreService.Stub::class.java, "grant")
    private val ungrantTransaction = getTransactCode(IKeystoreService.Stub::class.java, "ungrant")

    override val serviceName = "android.system.keystore2.IKeystoreService/default"
    override val processName = "keystore2"
    override val injectionCommand = "exec ./inject `pidof keystore2` libTEESimulator.so entry"

    private var teeInterceptor: SecurityLevelInterceptor? = null
    private var strongBoxInterceptor: SecurityLevelInterceptor? = null

    override fun onInterceptorSetup(service: IBinder, backdoor: IBinder) {
        setupSecurityLevelInterceptors(service, backdoor)
    }

    private fun setupSecurityLevelInterceptors(service: IBinder, backdoor: IBinder) {
        val ks = IKeystoreService.Stub.asInterface(service)

        val tee =
            kotlin
                .runCatching { ks.getSecurityLevel(SecurityLevel.TRUSTED_ENVIRONMENT) }
                .getOrNull()
        if (tee != null) {
            Logger.i("Registering for TEE SecurityLevel: $tee")
            val interceptor = SecurityLevelInterceptor(tee, SecurityLevel.TRUSTED_ENVIRONMENT)
            registerBinderInterceptor(backdoor, tee.asBinder(), interceptor)
            teeInterceptor = interceptor
        } else {
            Logger.i("No TEE SecurityLevel found")
        }

        val strongBox =
            kotlin.runCatching { ks.getSecurityLevel(SecurityLevel.STRONGBOX) }.getOrNull()
        if (strongBox != null) {
            Logger.i("Registering for StrongBox SecurityLevel: $strongBox")
            val interceptor = SecurityLevelInterceptor(strongBox, SecurityLevel.STRONGBOX)
            registerBinderInterceptor(backdoor, strongBox.asBinder(), interceptor)
            strongBoxInterceptor = interceptor
        } else {
            Logger.i("No StrongBox SecurityLevel found")
        }
    }

    override fun onPreTransact(
        txId: Long,
        target: IBinder,
        code: Int,
        flags: Int,
        callingUid: Int,
        callingPid: Int,
        data: Parcel,
    ): Result {
        when (code) {
            getSecurityLevelTransaction -> {
                logging(txId, "getSecurityLevel", callingUid, callingPid, data)
            }
            updateSubcomponentTransaction -> {
                logging(txId, "updateSubcomponent", callingUid, callingPid, data)
            }
            listEntriesTransaction -> {
                logging(txId, "listEntries", callingUid, callingPid, data)
            }
            deleteKeyTransaction -> {
                logging(txId, "deleteKey", callingUid, callingPid, data)
                return Continue
            }
            grantTransaction -> {
                logging(txId, "grant", callingUid, callingPid, data)
            }
            ungrantTransaction -> {
                logging(txId, "ungrant", callingUid, callingPid, data)
            }
            getKeyEntryTransaction -> {
                logging(txId, "getKeyEntry", callingUid, callingPid, data, false)
                if (!KeyBoxUtils.hasKeyboxes()) return Skip
                try {
                    data.enforceInterface(IKeystoreService.DESCRIPTOR)
                    val descriptor = data.readTypedObject(KeyDescriptor.CREATOR) ?: return Skip
                    val keyIdentifier = SecurityLevelInterceptor.Key(callingUid, descriptor.alias)
                    if (SecurityLevelInterceptor.aliasToFingerprintMap.containsKey(keyIdentifier))
                        return Continue
                    if (PkgConfig.needGenerate(callingUid)) {
                        val response = SecurityLevelInterceptor.getKeyResponse(keyIdentifier)
                        if (response != null) {
                            Logger.i(
                                "[TX_ID: $txId] Found generated response for uid=$callingUid alias=${descriptor.alias}"
                            )
                            return createTypedObjectReply(response)
                        } else {
                            Logger.e(
                                "[TX_ID: $txId] No generated response found for uid=$callingUid alias=${descriptor.alias}"
                            )
                            val nullParcel = Parcel.obtain()
                            nullParcel.writeTypedObject(null as KeyEntryResponse?, 0)
                            return OverrideReply(0, nullParcel)
                        }
                    } else if (PkgConfig.needHack(callingUid)) {
                        if (
                            SecurityLevelInterceptor.shouldSkipLeafHack(
                                callingUid,
                                descriptor.alias,
                            )
                        ) {
                            Logger.i(
                                "[TX_ID: $txId] Skip leaf hack for uid=$callingUid alias=${descriptor.alias}"
                            )
                            val response = SecurityLevelInterceptor.getKeyResponse(keyIdentifier)
                            if (response != null) {
                                Logger.i(
                                    "[TX_ID: $txId] Found generated response for uid=$callingUid alias=${descriptor.alias}"
                                )
                                return createTypedObjectReply(response)
                            } else {
                                Logger.e(
                                    "[TX_ID: $txId] No generated response found for uid=$callingUid alias=${descriptor.alias}"
                                )
                                val nullParcel = Parcel.obtain()
                                nullParcel.writeTypedObject(null as KeyEntryResponse?, 0)
                                return OverrideReply(0, nullParcel)
                            }
                        } else {
                            Logger.i(
                                "[TX_ID: $txId] Proceeding with leaf hack for uid=$callingUid alias=${descriptor.alias}"
                            )
                            return Continue
                        }
                    }
                } catch (e: Exception) {
                    Logger.e(
                        "[TX_ID: $txId] Exception in onPreTransact uid=$callingUid pid=$callingPid!",
                        e,
                    )
                }
            }
        }
        return super.onPreTransact(txId, target, code, flags, callingUid, callingPid, data)
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
    ): Result {
        if (target != keystore || reply == null) return Skip
        if (reply.hasException()) return Skip

        if (code == deleteKeyTransaction && resultCode == 0) {
            logging(txId, "post deleteKey", callingUid, callingPid, data, false)
            data.enforceInterface("android.system.keystore2.IKeystoreService")

            val keyDescriptor = data.readTypedObject(KeyDescriptor.CREATOR)
            if (keyDescriptor == null || keyDescriptor.domain == 0) return Skip

            SecurityLevelInterceptor.keys.remove(
                SecurityLevelInterceptor.Key(callingUid, keyDescriptor.alias)
            )

            return Skip
        } else if (code == getKeyEntryTransaction) {
            logging(txId, "post getKeyEntry", callingUid, callingPid, data, false)
            try {
                // We must use the certificate from the REPLY to get the hash, as that's the
                // ground truth of what the keystore is returning at this moment.
                val initialPosition = reply.dataPosition()
                val response = reply.readTypedObject(KeyEntryResponse.CREATOR)

                if (response == null) return Skip
                reply.setDataPosition(initialPosition) // Reset position for potential pass-through

                val chain = CertificateUtils.run { response.getCertificateChain() }
                val fingerprint = getPublicKeyFingerprint(chain)

                if (
                    fingerprint != null &&
                        SecurityLevelInterceptor.userProvidedKeyFingerprints.contains(fingerprint)
                ) {
                    val keyDescriptor = data.readTypedObject(KeyDescriptor.CREATOR) // For logging
                    Logger.d("Fingerprint for ${keyDescriptor?.alias}: $fingerprint")
                    Logger.w(
                        "Bypassing cert hack for key '${keyDescriptor?.alias}' based on its public key fingerprint."
                    )
                    return Skip
                }

                // If the fingerprint is not on the ignore list, it's a legitimate target for
                // hacking.
                if (chain != null) {
                    val newChain = CertificateHack.hackCertificateChain(chain, callingUid)
                    response.putCertificateChain(newChain).getOrThrow()
                    Logger.i("Hacked certificate for uid=$callingUid")
                    return createTypedObjectReply(response) // Return the modified response
                }
            } catch (t: Throwable) {
                Logger.e("Failed to handle getKeyEntry of uid=$callingUid pid=$callingPid!", t)
            }
        }
        return super.onPostTransact(
            txId,
            target,
            code,
            flags,
            callingUid,
            callingPid,
            data,
            reply,
            resultCode,
        )
    }
}
