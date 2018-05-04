/*
 * Copyright (c) 2018.
 *
 * This file is part of ProcessManager.
 *
 * ProcessManager is free software: you can redistribute it and/or modify it under the terms of version 2.1 of the
 * GNU Lesser General Public License as published by the Free Software Foundation.
 *
 * ProcessManager is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even
 * the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License along with ProcessManager.  If not,
 * see <http://www.gnu.org/licenses/>.
 */

package uk.ac.bournemouth.darwin.auth

import android.accounts.*
import android.content.Context
import android.content.Intent
import android.os.Build.VERSION
import android.os.Build.VERSION_CODES
import android.os.Bundle
import android.os.Process
import android.support.annotation.RequiresApi
import android.support.annotation.StringRes
import android.util.Base64
import android.util.Log
import java.io.IOException
import java.math.BigInteger
import java.net.HttpURLConnection
import java.net.URI
import java.nio.ByteBuffer
import java.nio.channels.Channels
import java.security.KeyFactory
import java.security.NoSuchAlgorithmException
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey
import java.security.spec.KeySpec
import java.security.spec.RSAPrivateKeySpec
import java.util.*
import javax.crypto.Cipher


/**
 * An authenticator taht authenticates against the darwin system.
 * @constructor Create a new authenticator.
 * @param context The context used to resolve context dependent values.
 */
class DarwinAuthenticator(private val context: Context) : AbstractAccountAuthenticator(context) {

    private class ChallengeInfo(val responseUri: URI, val data: ByteArray?, val version: Int)


    private class StaleCredentialsException : Exception()// The exception itself is enough

    private data class AuthenticatorKeyInfo(val keyId: Long, val privateKey: RSAPrivateKey)

    init {
        PRNGFixes.ensureApplied()
    }


    override fun editProperties(response: AccountAuthenticatorResponse, accountType: String): Bundle? {
        response.onError(ERROR_UNSUPPORTED_OPERATION, ERRORMSG_UNSUPPORTED_OPERATION)
        return null
    }

    private fun errorResult(@StringRes message: Int) = context.getString(message).toErrorBundle()

    @Throws(NetworkErrorException::class)
    override fun addAccount(response: AccountAuthenticatorResponse,
                            accountType: String,
                            authTokenType: String?,
                            requiredFeatures: Array<String>?,
                            options: Bundle): Bundle {
        Log.i(TAG,
              "addAccount() called with: response = [$response], accountType = [$accountType], authTokenType = [$authTokenType], requiredFeatures = [${Arrays.toString(
                  requiredFeatures)}], options = [$options]")

        if (!(authTokenType == null || DWN_ACCOUNT_TOKEN_TYPE == authTokenType)) {
            return errorResult(R.string.error_invalid_tokenType)
        }
        return context.darwinAuthenticatorActivity(null, options.authBase, response = response).toResultBundle()
    }

    @Throws(NetworkErrorException::class)
    override fun confirmCredentials(response: AccountAuthenticatorResponse, account: Account, options: Bundle): Bundle {
        val am = AccountManager.get(context)
        val intent = context.darwinAuthenticatorActivity(account,
                                                         am.getUserData(account, KEY_AUTH_BASE),
                                                         true,
                                                         am.getUserData(account, KEY_KEYID).toLongOrNull() ?: -1L,
                                                         response)
        return intent.toResultBundle()
    }

    @Throws(NetworkErrorException::class)
    override fun getAuthToken(response: AccountAuthenticatorResponse,
                              account: Account,
                              authTokenType: String,
                              options: Bundle): Bundle? {
        Log.d(TAG,
              "getAuthToken() called with: response = [$response], account = [$account], authTokenType = [$authTokenType], options = [${toString(
                  options)}]")
        if (authTokenType != DWN_ACCOUNT_TOKEN_TYPE) {
            response.onError(ERRNO_INVALID_TOKENTYPE, "invalid authTokenType")
            return null // the response has the error
        }
        val am = AccountManager.get(context)
        if (am.accounts.none { it == account }) {
            response.onError(ERROR_INVALID_ACCOUNT, "The account '$account' does not exist")
        }
        //    if(! hasAccount(am, account)) {
        //      throw new IllegalArgumentException("The provided account does not exist");
        //    }

        if (!isAuthTokenAllowed(response, account, options)) {
            return requestAuthTokenPermission(response, account, options)
        }

        val authBaseUrl: String = getAuthBase(am, account)

        try {
            val authKeyInfo = getAuthKeyInfo(account)
            if (authKeyInfo == null || authKeyInfo.keyId < 0) {
                // We are in an invalid state. We no longer have a private key. Redo authentication.
                return initiateUpdateCredentials(account, authBaseUrl)
            }

            for (tries in 0 until AUTHTOKEN_RETRIEVE_TRY_COUNT) {
                // Get challenge
                try {

                    val challenge = readChallenge(authBaseUrl, authKeyInfo)

                    if (challenge?.data == null) {
                        return initiateUpdateCredentials(account, authBaseUrl)
                    }

                    val responseBuffer = base64encode(
                        encrypt(challenge.data, authKeyInfo.privateKey, challenge.version))

                    val conn = challenge.responseUri.toURL().openConnection() as HttpURLConnection

                    try {
                        writeResponse(conn, responseBuffer)
                        try {
                            Channels.newChannel(conn.inputStream).use { inChannel ->
                                val buffer = ByteBuffer.allocate(MAX_TOKEN_SIZE)
                                val count = inChannel.read(buffer)
                                if (count < 0 || count >= MAX_TOKEN_SIZE) {
                                    response.onError(ERROR_INVALID_TOKEN_SIZE,
                                                     "The token size is not in a supported range")
                                    return null // the response has the error
                                    // Can't handle that
                                }
                                val cookie = ByteArray(buffer.position())
                                buffer.rewind()
                                buffer.get(cookie)
                                for (b in cookie) {
                                    val c = b.toChar()
                                    if (!(c in 'A'..'Z' || c in 'a'..'z' ||
                                          c in '0'..'9' || c == '+' || c == '/' ||
                                          c == '=' || c == ' ' || c == '-' || c == '_' || c == ':')) {
                                        response.onError(ERROR_INVALID_TOKEN,
                                                         "The token contains illegal characters (${String(cookie)}]")
                                        return null
                                    }
                                }

                                return createResultBundle(account, cookie)
                            }
                        } catch (e: IOException) {
                            if (conn.responseCode != HttpURLConnection.HTTP_UNAUTHORIZED) {
                                val intent = context.darwinAuthenticatorActivity(null, authBaseUrl, response = response)
                                // reauthenticate
                                return intent.toResultBundle()

                            } else if (conn.responseCode != HttpURLConnection.HTTP_NOT_FOUND) { // We try again if we didn't get the right code.
                                val result = Bundle()
                                result.putInt(AccountManager.KEY_ERROR_CODE, conn.responseCode)
                                result.putString(AccountManager.KEY_ERROR_MESSAGE, e.message)
                                return result
                            }
                            throw e
                        }

                    } finally {
                        conn.disconnect()
                    }

                } catch (e: IOException) {
                    throw NetworkErrorException(e)
                }

            }
            return errorResult(R.string.err_unable_to_get_auth_key)
        } catch (e: StaleCredentialsException) {
            return context.darwinAuthenticatorActivity(account, authBaseUrl).toResultBundle()
        }

    }


    private fun initiateUpdateCredentials(account: Account, authBaseUrl: String): Bundle {
        return context.darwinAuthenticatorActivity(account, authBaseUrl).toResultBundle()
    }

    private fun requestAuthTokenPermission(response: AccountAuthenticatorResponse,
                                           account: Account,
                                           options: Bundle): Bundle {
        val intent = context.authTokenPermissionActivity(account,
                                                         options.getInt(AccountManager.KEY_CALLER_UID),
                                                         options.getString(AccountManager.KEY_ANDROID_PACKAGE_NAME))

        return intent.toResultBundle().also { response.onResult(it) }
    }

    private fun isAuthTokenAllowed(response: AccountAuthenticatorResponse, account: Account, options: Bundle): Boolean {
        Log.d(TAG,
              "isAuthTokenAllowed() called with: " + "response = [" + response + "], account = [" + account + "], options = " + options + ", myUid=[" + Process.myUid() +
              ']'.toString())
        if (!options.containsKey(AccountManager.KEY_CALLER_UID)) {
            return true /* customTokens disabled */
        }
        val callerUid = options.getInt(AccountManager.KEY_CALLER_UID, -1)
        val callerPackage: String? = when {
            VERSION.SDK_INT >= VERSION_CODES.ICE_CREAM_SANDWICH
                 -> options.getString(AccountManager.KEY_ANDROID_PACKAGE_NAME)

            else -> null
        }
        if (Process.myUid() == callerUid) {
            return true
        }
        val am = AccountManager.get(context)
        return isAllowedUid(am, account, callerUid, callerPackage)
    }

    private fun getAuthKeyInfo(account: Account): AuthenticatorKeyInfo? {
        val am = AccountManager.get(context)
        val privateKeyString = am.getUserData(account, KEY_PRIVATEKEY) ?: return null
        val privateKey = getPrivateKey(privateKeyString) ?: return null
        val keyId = am.getUserData(account, KEY_KEYID)?.toLongOrNull() ?: return null
        return AuthenticatorKeyInfo(keyId, privateKey)
    }

    override fun getAuthTokenLabel(authTokenType: String): String? {
        Log.i(TAG, "Getting token label")
        return when (authTokenType) {
            DWN_ACCOUNT_TOKEN_TYPE -> null
            else                   -> context.getString(R.string.authtoken_label)
        }
    }

    @Throws(NetworkErrorException::class)
    override fun updateCredentials(response: AccountAuthenticatorResponse,
                                   account: Account,
                                   authTokenType: String,
                                   options: Bundle): Bundle {
        val am = AccountManager.get(context)
        val authbase = am.getUserData(account, KEY_AUTH_BASE)

        val keyid = am.getUserData(account, KEY_KEYID).toLong()
        val intent = context.darwinAuthenticatorActivity(account, authbase, false, keyid, response)

        return intent.toResultBundle()
    }

    @Throws(NetworkErrorException::class)
    override fun hasFeatures(response: AccountAuthenticatorResponse,
                             account: Account,
                             features: Array<String?>): Bundle {
        Log.i(TAG,
              "hasFeatures() called with: response = [$response], account = [$account], features = ${features.contentDeepToString()}")
        val hasFeature = if (features.size == 1) {
            val am = AccountManager.get(context)
            if (am.accounts.none { it == account }) {
                false
            } else {
                val authbase = am.getUserData(account, KEY_AUTH_BASE)
                if (authbase == null) {
                    features[0] == null || DEFAULT_AUTH_BASE_URL == features[0]
                } else {
                    authbase == features[0] || features[0] == null && DEFAULT_AUTH_BASE_URL == authbase
                }
            }
        } else {
            false
        }
        return Bundle(1)
            .also {
                it.putBoolean(AccountManager.KEY_BOOLEAN_RESULT, hasFeature)
                Log.i(TAG, "hasFeatures() returned: $it -> $hasFeature")
            }
    }

    companion object {

        /** The argument name used to specify the base url for authentication.  */
        const val KEY_AUTH_BASE = "authbase"

        const val DEFAULT_AUTH_BASE_URL = "https://darwin.bournemouth.ac.uk/accountmgr/"
        const val KEY_PRIVATEKEY = "privatekey"
        const val KEY_KEYID = "keyid"
        const val KEY_ACCOUNT = "account"

        private const val CIPHERSUITE_V2 = "RSA/ECB/PKCS1Padding"
        private const val CIPHERSUITE_V1 = "RSA/NONE/NOPADDING"

        private const val CHALLENGE_VERSION_V2 = "2"
        private const val CHALLENGE_VERSION_V1 = "1"
        private const val HEADER_CHALLENGE_VERSION = "X-Challenge-version"

        const val KEY_ALGORITHM = "RSA"
        private const val AUTHTOKEN_RETRIEVE_TRY_COUNT = 5

        private const val TAG = "DarwinAuthenticator"
        private const val CHALLENGE_MAX = 4096
        private const val HEADER_RESPONSE = "X-Darwin-Respond"
        private const val MAX_TOKEN_SIZE = 1024
        private const val BASE64_FLAGS = Base64.URL_SAFE or Base64.NO_WRAP
        private const val ERRNO_INVALID_TOKENTYPE = AccountManager.ERROR_CODE_BAD_ARGUMENTS
        private const val ERROR_INVALID_TOKEN_SIZE = AccountManager.ERROR_CODE_REMOTE_EXCEPTION
        private const val ERROR_INVALID_TOKEN = AccountManager.ERROR_CODE_REMOTE_EXCEPTION
        private const val ERROR_INVALID_ACCOUNT = AccountManager.ERROR_CODE_BAD_ARGUMENTS
        private const val ERRORMSG_UNSUPPORTED_OPERATION = "Editing properties is not supported"
        private const val ERROR_UNSUPPORTED_OPERATION = AccountManager.ERROR_CODE_UNSUPPORTED_OPERATION
        private const val KEY_ALLOWED_UIDS = "allowedUids"

        @JvmStatic
        fun toString(options: Bundle): String {
            return options
                .keySet()
                .joinToString(", ", "[", "]") { key -> "$key=${options[key]}" }
        }

        @JvmStatic
        fun isAllowedUid(am: AccountManager, account: Account, uid: Int, callerPackage: String?): Boolean {
            val allowedUidsString = am.getUserData(account, KEY_ALLOWED_UIDS)
            Log.d(TAG,
                  "isAllowedUid() called with: am = [$am], account = [$account], uid = [$uid], callerPackage = [$callerPackage], allowedUidString=[$allowedUidsString]")
            if (allowedUidsString.isNullOrEmpty()) return false

            return allowedUidsString
                .split(',')
                .any { it.trim().toInt() == uid }
                .also { Log.d(TAG, "isAllowedUid() returned: $it") }
        }

        @JvmStatic
        fun addAllowedUid(am: AccountManager, account: Account, uid: Int) {
            val oldAllowedUids: String? = am.getUserData(account, KEY_ALLOWED_UIDS)
            val newAllowedUids: String = when {
                oldAllowedUids == null || oldAllowedUids.isEmpty()
                     -> Integer.toString(uid)

                else -> {
                    if (oldAllowedUids.split(',').any { it.trim().toInt() == uid }) return

                    "$oldAllowedUids,$uid"
                }
            }
            am.setUserData(account, KEY_ALLOWED_UIDS, newAllowedUids)
        }

        @JvmStatic
        fun removeAllowedUid(am: AccountManager, account: Account, uid: Int) {
            val allowedUidsString = am.getUserData(account, KEY_ALLOWED_UIDS)
            val uidString = uid.toString()

            Log.d(TAG,
                  "removeAllowedUid() called with: am = [$am], account = [$account], uid = [$uid], allowedUids=[$allowedUidsString], uidString=[$uidString]")

            if (allowedUidsString != null && !allowedUidsString.isEmpty()) {
                val newString = allowedUidsString
                    .splitToSequence(',')
                    .map { it.trim() }
                    .filter { it == uidString }
                    .joinToString(",")
                    .let { if (it.isEmpty()) null else it }

                am.setUserData(account, KEY_ALLOWED_UIDS, newString)

                Log.d(TAG, "removeAllowedUid($uid) stored: $newString was:$allowedUidsString")
            }
        }

        private fun encrypt(challenge: ByteArray?, privateKey: RSAPrivateKey, version: Int): ByteArray {
            val cipher = Cipher.getInstance(if (version == 1) CIPHERSUITE_V1 else CIPHERSUITE_V2)
            cipher.init(Cipher.ENCRYPT_MODE, privateKey)

            return cipher.doFinal(challenge)
        }

        @Throws(IOException::class)
        private fun writeResponse(conn: HttpURLConnection, response: ByteArray) {
            conn.doOutput = true
            conn.requestMethod = "POST"
            conn.setRequestProperty("Content-Type", "application/x-www-form-urlencoded;charset=utf8")
            conn.outputStream.use { out ->
                out.write("response=".toByteArray())
                out.write(response)
            }
        }

        private fun base64encode(input: ByteArray?): ByteArray {
            return Base64.encode(input, BASE64_FLAGS)
        }

        @Throws(IOException::class, StaleCredentialsException::class)
        private fun readChallenge(authBaseUrl: String, authenticatorKeyInfo: AuthenticatorKeyInfo): ChallengeInfo? {
            val challengeUrl = URI.create("${getChallengeUrl(authBaseUrl)}?keyid=${authenticatorKeyInfo.keyId}")
            val connection = challengeUrl.toURL().openConnection() as HttpURLConnection
            try {
                connection.instanceFollowRedirects = false// We should get the response url.
                val responseUrl: URI = connection.getHeaderField(HEADER_RESPONSE)?.let { URI.create(it) }
                                       ?: challengeUrl
                val version = when (connection.getHeaderField(HEADER_CHALLENGE_VERSION)) {
                    CHALLENGE_VERSION_V1 -> 1
                    CHALLENGE_VERSION_V2 -> 2
                    else                 -> -1
                }

                val responseCode = connection.responseCode
                if (responseCode == HttpURLConnection.HTTP_FORBIDDEN || responseCode == HttpURLConnection.HTTP_NOT_FOUND) {
                    return null
                } else if (responseCode >= 400) {
                    throw HttpResponseException(connection)
                }

                val inBuffer = ByteArray(CHALLENGE_MAX * 4 / 3)

                val readCount: Int = connection.inputStream.use { it.read(inBuffer) }

                val challengeBytes: ByteArray
                challengeBytes = if (version != 1) {
                    Base64.decode(inBuffer, 0, readCount, Base64.URL_SAFE)
                } else {
                    Arrays.copyOf(inBuffer, readCount)
                }
                return ChallengeInfo(responseUrl, challengeBytes, version)
            } finally {
                connection.disconnect()
            }
        }

        private fun getChallengeUrl(authBaseUrl: String): URI {
            return URI.create("${authBaseUrl}challenge")
        }

        @JvmStatic
        fun getAuthenticateUrl(authBaseUrl: String?): URI {
            return URI.create("${if (authBaseUrl.isNullOrEmpty()) DEFAULT_AUTH_BASE_URL else authBaseUrl}regkey")
        }

        @JvmStatic
        fun encodePrivateKey(privateKey: RSAPrivateKey): String {
            val result = StringBuilder()
            result.append(privateKey.modulus)
            result.append(':')
            result.append(privateKey.privateExponent)
            return result.toString()
        }

        @JvmStatic
        fun encodePublicKey(publicKey: RSAPublicKey): String {
            return buildString {
                append(Base64.encodeToString(publicKey.modulus.toByteArray(), BASE64_FLAGS))
                append(':')
                append(Base64.encodeToString(publicKey.publicExponent.toByteArray(), BASE64_FLAGS))
            }.also {
                Log.d(TAG, "Registering public key: (${publicKey.modulus}, ${publicKey.publicExponent}) $it")
            }
        }

    }

    private fun getPrivateKey(privateKeyString: String): RSAPrivateKey? {
        val keyfactory: KeyFactory
        try {
            keyfactory = KeyFactory.getInstance(KEY_ALGORITHM)
        } catch (e: NoSuchAlgorithmException) {
            Log.e(TAG, "The RSA algorithm isn't supported on your system", e)
            return null
        }

        val keyspec: KeySpec = run {
            val end = privateKeyString.indexOf(':')
            val modulus = BigInteger(privateKeyString.substring(0, end))

            val start = end + 1
            val privateExponent = BigInteger(privateKeyString.substring(start))
            RSAPrivateKeySpec(modulus, privateExponent)
        }
        return keyfactory.generatePrivate(keyspec) as RSAPrivateKey
    }
}

private const val EXPIRY_TIMEOUT = (1000 * 60 * 30).toLong() // 30 minutes

var Bundle.accountName: String?
    get() = getString(AccountManager.KEY_ACCOUNT_NAME)
    set(value) = putString(AccountManager.KEY_ACCOUNT_NAME, value)

var Bundle.accountType: String?
    get() = getString(AccountManager.KEY_ACCOUNT_TYPE)
    set(value) = putString(AccountManager.KEY_ACCOUNT_TYPE, value)

var Bundle.authToken: String?
    get() = getString(AccountManager.KEY_AUTHTOKEN)
    set(value) = putString(AccountManager.KEY_AUTHTOKEN, value)

var Bundle.customTokenExpiry: Long
    @RequiresApi(VERSION_CODES.M)
    get() = getLong(AbstractAccountAuthenticator.KEY_CUSTOM_TOKEN_EXPIRY, -1L)
    @RequiresApi(VERSION_CODES.M)
    set(value) = putLong(AbstractAccountAuthenticator.KEY_CUSTOM_TOKEN_EXPIRY, value)


var Bundle.authBase: String
    get() = getString(DarwinAuthenticator.KEY_AUTH_BASE, DarwinAuthenticator.DEFAULT_AUTH_BASE_URL)
    set(value) = putString(DarwinAuthenticator.KEY_AUTH_BASE, value)


private fun createResultBundle(account: Account, cookie: ByteArray): Bundle {
    return Bundle(4).apply {
        accountName = account.name
        accountType = DWN_ACCOUNT_TOKEN_TYPE
        authToken = String(cookie, UTF8)

        if (VERSION.SDK_INT >= VERSION_CODES.M) {
            customTokenExpiry = System.currentTimeMillis() + EXPIRY_TIMEOUT
        }

    }
}

fun getAuthBase(am: AccountManager, account: Account) =
    am.getUserData(account, DarwinAuthenticator.KEY_AUTH_BASE) ?: DarwinAuthenticator.DEFAULT_AUTH_BASE_URL

fun Intent.toResultBundle() = Bundle(1).apply { putParcelable(AccountManager.KEY_INTENT, this@toResultBundle) }

private fun String.toErrorBundle() =
    Bundle(1).apply { putString(AccountManager.KEY_ERROR_MESSAGE, this@toErrorBundle) }

/** The account type supported by the authenticator.  */
const val DWN_ACCOUNT_TYPE = "uk.ac.bournemouth.darwin.account"
/** The token type for darwin accounts. For now there is only this type.  */
const val DWN_ACCOUNT_TOKEN_TYPE = "uk.ac.bournemouth.darwin.auth"