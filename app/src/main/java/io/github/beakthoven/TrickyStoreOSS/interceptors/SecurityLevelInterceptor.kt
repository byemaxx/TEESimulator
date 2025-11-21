/*
 * Copyright 2025 Dakkshesh <beakthoven@gmail.com>
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

package io.github.beakthoven.TrickyStoreOSS.interceptors

import android.hardware.security.keymint.KeyParameter
import android.hardware.security.keymint.KeyParameterValue
import android.hardware.security.keymint.Tag
import android.os.IBinder
import android.os.Parcel
import android.system.keystore2.Authorization
import android.system.keystore2.IKeystoreSecurityLevel
import android.system.keystore2.KeyDescriptor
import android.system.keystore2.KeyEntryResponse
import android.system.keystore2.KeyMetadata
import androidx.annotation.Keep
import io.github.beakthoven.TrickyStoreOSS.CertificateGen
import io.github.beakthoven.TrickyStoreOSS.CertificateUtils
import io.github.beakthoven.TrickyStoreOSS.config.PkgConfig
import io.github.beakthoven.TrickyStoreOSS.interceptors.InterceptorUtils.getTransactCode
import io.github.beakthoven.TrickyStoreOSS.interceptors.InterceptorUtils.hasException
import io.github.beakthoven.TrickyStoreOSS.logging.Logger
import io.github.beakthoven.TrickyStoreOSS.putCertificateChain
import java.security.KeyPair
import java.security.cert.Certificate
import java.util.concurrent.ConcurrentHashMap

class SecurityLevelInterceptor(
    private val original: IKeystoreSecurityLevel,
    private val level: Int,
) : BinderInterceptor() {
    companion object {
        private val createOperationTransaction =
            getTransactCode(IKeystoreSecurityLevel.Stub::class.java, "createOperation")
        private val generateKeyTransaction =
            getTransactCode(IKeystoreSecurityLevel.Stub::class.java, "generateKey")
        private val importKeyTransaction =
            getTransactCode(IKeystoreSecurityLevel.Stub::class.java, "importKey")
        private val importWrappedKeyTransaction =
            getTransactCode(IKeystoreSecurityLevel.Stub::class.java, "importWrappedKey")
        private val deleteKeyTransaction =
            getTransactCode(IKeystoreSecurityLevel.Stub::class.java, "deleteKey")
        private val convertStorageKeyToEphemeralTransaction =
            getTransactCode(IKeystoreSecurityLevel.Stub::class.java, "convertStorageKeyToEphemeral")

        @Keep val keys = ConcurrentHashMap<Key, Info>()

        // The set of fingerprints of public keys that were user-provided.
        @Keep val userProvidedKeyFingerprints = ConcurrentHashMap.newKeySet<String>()
        // A map to allow for cleanup on deletion: Key(uid, alias) -> "Fingerprint"
        @Keep val aliasToFingerprintMap = ConcurrentHashMap<Key, String>()

        @Keep val keyPairs = ConcurrentHashMap<Key, Pair<KeyPair, List<Certificate>>>()

        @Keep val skipLeafHacks = ConcurrentHashMap<Key, Boolean>()

        @Keep fun getKeyResponse(key: Key): KeyEntryResponse? = keys[key]?.response

        @Keep
        fun getKeyResponse(uid: Int, alias: String): KeyEntryResponse? =
            getKeyResponse(Key(uid, alias))

        @Keep
        fun getKeyPairs(uid: Int, alias: String): Pair<KeyPair, List<Certificate>>? =
            keyPairs[Key(uid, alias)]

        @Keep fun shouldSkipLeafHack(key: Key): Boolean = skipLeafHacks[key] ?: false

        @Keep
        fun shouldSkipLeafHack(uid: Int, alias: String): Boolean =
            shouldSkipLeafHack(Key(uid, alias))
    }

    data class Key(val uid: Int, val alias: String)

    data class Info(val keyPair: KeyPair, val response: KeyEntryResponse)

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
            createOperationTransaction -> {
                logging(txId, "createOperation", callingUid, callingPid, data)
            }
            importKeyTransaction -> {
                logging(txId, "importKey", callingUid, callingPid, data)
                return Continue
            }
            importWrappedKeyTransaction -> {
                logging(txId, "importWrappedKey", callingUid, callingPid, data)
            }
            convertStorageKeyToEphemeralTransaction -> {
                logging(txId, "convertStorageKeyToEphemeral", callingUid, callingPid, data)
            }
            deleteKeyTransaction -> {
                logging(txId, "deleteKey", callingUid, callingPid, data, false)
                runCatching {
                        data.enforceInterface(IKeystoreSecurityLevel.DESCRIPTOR)
                        val keyDescriptor =
                            data.readTypedObject(KeyDescriptor.CREATOR) ?: return Skip
                        val keyIdentifier = Key(callingUid, keyDescriptor.alias)

                        val fingerprintToRemove = aliasToFingerprintMap.remove(keyIdentifier)
                        if (fingerprintToRemove != null) {
                            userProvidedKeyFingerprints.remove(fingerprintToRemove)
                            Logger.i(
                                "Cleaned up ignored key fingerprint for alias '${keyDescriptor.alias}' on deletion."
                            )
                        }
                    }
                    .onFailure { Logger.e("Parse importKey request", it) }
                return Skip
            }
            generateKeyTransaction -> {
                logging(txId, "generateKey", callingUid, callingPid, data, false)
                runCatching {
                        data.enforceInterface(IKeystoreSecurityLevel.DESCRIPTOR)
                        val keyDescriptor =
                            data.readTypedObject(KeyDescriptor.CREATOR) ?: return@runCatching
                        val attestationKeyDescriptor = data.readTypedObject(KeyDescriptor.CREATOR)
                        val params = data.createTypedArray(KeyParameter.CREATOR)!!
                        val aFlags = data.readInt()
                        val entropy = data.createByteArray()
                        val kgp = CertificateGen.KeyGenParameters(params)
                        if (PkgConfig.needGenerate(callingUid)) {
                            val pair =
                                CertificateGen.generateKeyPair(
                                    callingUid,
                                    keyDescriptor,
                                    attestationKeyDescriptor,
                                    kgp,
                                    level,
                                ) ?: return@runCatching
                            keyPairs[Key(callingUid, keyDescriptor.alias)] =
                                Pair(pair.first, pair.second)
                            val response =
                                buildResponse(
                                    pair.second,
                                    kgp,
                                    attestationKeyDescriptor ?: keyDescriptor,
                                )
                            keys[Key(callingUid, keyDescriptor.alias)] = Info(pair.first, response)
                            val p = Parcel.obtain()
                            p.writeNoException()
                            p.writeTypedObject(response.metadata, 0)
                            return OverrideReply(0, p)
                        } else if (PkgConfig.needHack(callingUid)) {
                            if (
                                kgp.attestationChallenge != null || attestationKeyDescriptor != null
                            ) {
                                Logger.i(
                                    "Generating key in generation mode for attestation: uid=$callingUid alias=${keyDescriptor.alias}"
                                )
                                val pair =
                                    CertificateGen.generateKeyPair(
                                        callingUid,
                                        keyDescriptor,
                                        attestationKeyDescriptor,
                                        kgp,
                                        level,
                                    ) ?: return@runCatching
                                keyPairs[Key(callingUid, keyDescriptor.alias)] =
                                    Pair(pair.first, pair.second)
                                val response =
                                    buildResponse(
                                        pair.second,
                                        kgp,
                                        attestationKeyDescriptor ?: keyDescriptor,
                                    )
                                keys[Key(callingUid, keyDescriptor.alias)] =
                                    Info(pair.first, response)
                                SecurityLevelInterceptor.skipLeafHacks[
                                        Key(callingUid, keyDescriptor.alias)] = true
                                val p = Parcel.obtain()
                                p.writeNoException()
                                p.writeTypedObject(response.metadata, 0)
                                return OverrideReply(0, p)
                            } else {
                                skipLeafHacks.remove(Key(callingUid, keyDescriptor.alias))
                                Logger.i(
                                    "Cleared skip flag for non-attestation key: uid=$callingUid alias=${keyDescriptor.alias}"
                                )
                                return Skip
                            }
                        }
                    }
                    .onFailure { Logger.e("Parse generateKey request", it) }
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
        if (reply == null || reply.hasException()) return Skip

        if (code == importKeyTransaction && resultCode == 0) {
            logging(txId, "post importKey", callingUid, callingPid, data, false)

            runCatching {
                    data.enforceInterface(IKeystoreSecurityLevel.DESCRIPTOR)
                    val keyDescriptor = data.readTypedObject(KeyDescriptor.CREATOR) ?: return Skip

                    Logger.w("Remove keys ($callingUid, ${keyDescriptor.alias})")
                    SecurityLevelInterceptor.keys.remove(
                        SecurityLevelInterceptor.Key(callingUid, keyDescriptor.alias)
                    )

                    val metadata = reply.readTypedObject(KeyMetadata.CREATOR)
                    val chain = CertificateUtils.run { metadata.getCertificateChain() }
                    val fingerprint = getPublicKeyFingerprint(chain)
                    Logger.d("Fingerprint for ${keyDescriptor.alias}: $fingerprint")
                    if (fingerprint != null) {
                        val keyIdentifier = Key(callingUid, keyDescriptor.alias)
                        Logger.w(
                            "Key '${keyDescriptor.alias}' imported. Storing fingerprint to ignore list."
                        )
                        userProvidedKeyFingerprints.add(fingerprint)
                        aliasToFingerprintMap[keyIdentifier] = fingerprint
                    }
                }
                .onFailure { Logger.e("Parse importKey request", it) }
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

    private fun buildResponse(
        chain: List<Certificate>,
        params: CertificateGen.KeyGenParameters,
        descriptor: KeyDescriptor,
    ): KeyEntryResponse {
        val response = KeyEntryResponse()
        val metadata = KeyMetadata()
        metadata.keySecurityLevel = level
        metadata.putCertificateChain(chain.toTypedArray()).getOrThrow()
        val d = KeyDescriptor()
        d.domain = descriptor.domain
        d.nspace = descriptor.nspace
        metadata.key = d
        val authorizations = ArrayList<Authorization>()
        var a: Authorization
        for (i in params.purpose.toList()) {
            a = Authorization()
            a.keyParameter = KeyParameter()
            a.keyParameter.tag = Tag.PURPOSE
            a.keyParameter.value = KeyParameterValue.keyPurpose(i)
            a.securityLevel = level
            authorizations.add(a)
        }
        for (i in params.digest.toList()) {
            a = Authorization()
            a.keyParameter = KeyParameter()
            a.keyParameter.tag = Tag.DIGEST
            a.keyParameter.value = KeyParameterValue.digest(i)
            a.securityLevel = level
            authorizations.add(a)
        }
        a = Authorization()
        a.keyParameter = KeyParameter()
        a.keyParameter.tag = Tag.ALGORITHM
        a.keyParameter.value = KeyParameterValue.algorithm(params.algorithm)
        a.securityLevel = level
        authorizations.add(a)
        a = Authorization()
        a.keyParameter = KeyParameter()
        a.keyParameter.tag = Tag.KEY_SIZE
        a.keyParameter.value = KeyParameterValue.integer(params.keySize)
        a.securityLevel = level
        authorizations.add(a)
        a = Authorization()
        a.keyParameter = KeyParameter()
        a.keyParameter.tag = Tag.EC_CURVE
        a.keyParameter.value = KeyParameterValue.ecCurve(params.ecCurve)
        a.securityLevel = level
        authorizations.add(a)
        a = Authorization()
        a.keyParameter = KeyParameter()
        a.keyParameter.tag = Tag.NO_AUTH_REQUIRED
        a.keyParameter.value = KeyParameterValue.boolValue(true)
        a.securityLevel = level
        authorizations.add(a)
        metadata.authorizations = authorizations.toTypedArray<Authorization>()
        response.metadata = metadata
        response.iSecurityLevel = original
        return response
    }
}
