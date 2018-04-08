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
import android.os.Build
import android.os.Bundle
import android.os.Process
import android.support.annotation.StringRes
import android.util.Base64
import android.util.Log
import uk.ac.bournemouth.darwin.auth.DarwinAuthenticator.Companion.ACCOUNT_TOKEN_TYPE

import javax.crypto.Cipher

import java.io.IOException
import java.math.BigInteger
import java.net.HttpURLConnection
import java.net.URI
import java.nio.ByteBuffer
import java.nio.channels.Channels
import java.security.GeneralSecurityException
import java.security.KeyFactory
import java.security.NoSuchAlgorithmException
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey
import java.security.spec.InvalidKeySpecException
import java.security.spec.KeySpec
import java.security.spec.RSAPrivateKeySpec
import java.util.Arrays


/**
 * An authenticator taht authenticates against the darwin system.
 * @constructor Create a new authenticator.
 * @param context The context used to resolve context dependent values.
 */
class DarwinAuthenticator(private val context: Context) : AbstractAccountAuthenticator(context) {

    private class ChallengeInfo(val responseUri: URI, val data: ByteArray?, val version: Int)

    // Object Initialization
    private class StaleCredentialsException : Exception()// The exception itself is enough

    private data class KeyInfo(val keyId: Long, val privateKey: RSAPrivateKey)

    init {
        PRNGFixes.ensureApplied()
    }


    override fun editProperties(response: AccountAuthenticatorResponse, accountType: String): Bundle? {
        response.onError(ERROR_UNSUPPORTED_OPERATION, ERRORMSG_UNSUPPORTED_OPERATION)
        return null
    }

    private fun invalidResult(@StringRes message: Int) = Bundle(1).apply {
        putString(AccountManager.KEY_ERROR_MESSAGE, context.getString(message))
    }

    @Throws(NetworkErrorException::class)
    override fun addAccount(response: AccountAuthenticatorResponse,
                            accountType: String,
                            authTokenType: String?,
                            requiredFeatures: Array<String>,
                            options: Bundle): Bundle {
        Log.i(TAG,
              "addAccount() called with: response = [$response], accountType = [$accountType], authTokenType = [$authTokenType], requiredFeatures = [${Arrays.toString(
                  requiredFeatures)}], options = [$options]")

        if (!(authTokenType == null || ACCOUNT_TOKEN_TYPE == authTokenType)) {
            return invalidResult(R.string.error_invalid_tokenType)
        }
        val intent = Intent(context, DarwinAuthenticatorActivity::class.java)
        intent.putExtra(AccountManager.KEY_ACCOUNT_AUTHENTICATOR_RESPONSE, response)
        intent.putExtra(KEY_AUTH_BASE, getAuthBase(options))
        val bundle = Bundle()
        bundle.putParcelable(AccountManager.KEY_INTENT, intent)
        return bundle
    }

    @Throws(NetworkErrorException::class)
    override fun confirmCredentials(response: AccountAuthenticatorResponse, account: Account, options: Bundle): Bundle {
        val am = AccountManager.get(context)
        val intent = Intent(context, DarwinAuthenticatorActivity::class.java)
        intent.putExtra(AccountManager.KEY_ACCOUNT_AUTHENTICATOR_RESPONSE, response)
        intent.putExtra(DarwinAuthenticatorActivity.PARAM_ACCOUNT, account)
        intent.putExtra(KEY_AUTH_BASE, am.getUserData(account, KEY_AUTH_BASE))
        intent.putExtra(DarwinAuthenticatorActivity.PARAM_CONFIRM, true)
        val keyid = java.lang.Long.parseLong(am.getUserData(account, KEY_KEYID))
        intent.putExtra(DarwinAuthenticatorActivity.PARAM_KEYID, keyid)
        val bundle = Bundle()
        bundle.putParcelable(AccountManager.KEY_INTENT, intent)
        return bundle
    }

    @Throws(NetworkErrorException::class)
    override fun getAuthToken(response: AccountAuthenticatorResponse,
                              account: Account,
                              authTokenType: String,
                              options: Bundle): Bundle? {
        Log.d(TAG,
              "getAuthToken() called with: " + "response = [" + response + "], account = [" + account + "], authTokenType = [" + authTokenType + "], options = [" + toString(
                  options) +
              ']'.toString())
        if (authTokenType != ACCOUNT_TOKEN_TYPE) {
            response.onError(ERRNO_INVALID_TOKENTYPE, "invalid authTokenType")
            return null // the response has the error
        }
        val am = AccountManager.get(context)
        //    if(! hasAccount(am, account)) {
        //      throw new IllegalArgumentException("The provided account does not exist");
        //    }

        if (!isAuthTokenAllowed(response, account, options)) {
            return requestAuthTokenPermission(response, account, options)
        }

        var authBaseUrl: String? = am.getUserData(account, KEY_AUTH_BASE)
        if (authBaseUrl == null) {
            authBaseUrl = DEFAULT_AUTH_BASE_URL
        }

        try {
            val keyInfo = getKeyInfo(account)
            if (keyInfo == null || keyInfo.keyId < 0) {
                // We are in an invalid state. We no longer have a private key. Redo authentication.
                return initiateUpdateCredentials(account, authBaseUrl)
            }

            for (tries in 0 until AUTHTOKEN_RETRIEVE_TRY_COUNT) {
                // Get challenge
                try {

                    val challenge = readChallenge(account, authBaseUrl, keyInfo)

                    if (challenge == null || challenge.data == null) {
                        return initiateUpdateCredentials(account, authBaseUrl)
                    }

                    val responseBuffer = base64encode(encrypt(challenge.data, keyInfo.privateKey, challenge.version))
                    /*
          if (BuildConfig.DEBUG) {
            Log.d(TAG, "Challenge: "+new String(challenge));
            Log.d(TAG, "Response: "+new String(responseBuffer));
            Log.d(TAG, "Private key exp: "+Base64.encodeToString(keyInfo.privateKey.getPrivateExponent().toByteArray(),0)+
                       " modulus: "+Base64.encodeToString(keyInfo.privateKey.getModulus().toByteArray(), 0));
          }
*/

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
                                        response.onError(ERROR_INVALID_TOKEN, "The token contains illegal characters (${String(cookie)}]")
                                        return null
                                    }
                                }

                                return createResultBundle(account, cookie)
                            }
                        } catch (e: IOException) {
                            if (conn.responseCode != HttpURLConnection.HTTP_UNAUTHORIZED) {
                                // reauthenticate
                                val intent = Intent(context, DarwinAuthenticatorActivity::class.java)
                                intent.putExtra(AccountManager.KEY_ACCOUNT_AUTHENTICATOR_RESPONSE, response)
                                return intent.toBundle()

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
            return Bundle(1).apply { putString(AccountManager.KEY_ERROR_MESSAGE, "Could not get authentication key") }
        } catch (e: StaleCredentialsException) {
            val result = Bundle()
            result.putParcelable(AccountManager.KEY_INTENT, getUpdateCredentialsBaseIntent(account, authBaseUrl))
            return result
        }

    }

    private fun initiateUpdateCredentials(account: Account, authBaseUrl: String): Bundle {
        val result = Bundle()
        result.putParcelable(AccountManager.KEY_INTENT, getUpdateCredentialsBaseIntent(account, authBaseUrl))
        return result
    }

    private fun requestAuthTokenPermission(response: AccountAuthenticatorResponse,
                                           account: Account,
                                           options: Bundle): Bundle {
        val intent = context.authTokenPermissionActivity(account,
                                                         options.getInt(AccountManager.KEY_CALLER_UID),
                                                         options.getString(AccountManager.KEY_ANDROID_PACKAGE_NAME))

        val bundle = Bundle(1)
        bundle.putParcelable(AccountManager.KEY_INTENT, intent)
        response.onResult(bundle)
        return bundle
    }

    private fun isAuthTokenAllowed(response: AccountAuthenticatorResponse, account: Account, options: Bundle): Boolean {
        Log.d(TAG,
              "isAuthTokenAllowed() called with: " + "response = [" + response + "], account = [" + account + "], options = " + options + ", myUid=[" + Process.myUid() +
              ']'.toString())
        if (!options.containsKey(AccountManager.KEY_CALLER_UID)) {
            return true /* customTokens disabled */
        }
        val callerUid = options.getInt(AccountManager.KEY_CALLER_UID, -1)
        val callerPackage: String?
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.ICE_CREAM_SANDWICH) {
            callerPackage = options.getString(AccountManager.KEY_ANDROID_PACKAGE_NAME)
        } else {
            callerPackage = null
        }
        if (Process.myUid() == callerUid) {
            return true
        }
        val am = AccountManager.get(context)
        return isAllowedUid(am, account, callerUid, callerPackage)
    }

    private fun getKeyInfo(account: Account): KeyInfo? {
        val am = AccountManager.get(context)
        val privateKeyString = am.getUserData(account, KEY_PRIVATEKEY) ?: return null
        val privateKey = getPrivateKey(privateKeyString) ?: return null
        val keyId = am.getUserData(account, KEY_KEYID)?.toLongOrNull() ?: return null
        return KeyInfo(keyId, privateKey)
    }

    override fun getAuthTokenLabel(authTokenType: String): String? {
        Log.i(TAG, "Getting token label")
        return when (authTokenType) {
            ACCOUNT_TOKEN_TYPE -> null
            else               -> context.getString(R.string.authtoken_label)
        }
    }

    @Throws(NetworkErrorException::class)
    override fun updateCredentials(response: AccountAuthenticatorResponse,
                                   account: Account,
                                   authTokenType: String,
                                   options: Bundle): Bundle {
        val am = AccountManager.get(context)
        val authbase = am.getUserData(account, KEY_AUTH_BASE)
        val intent = getUpdateCredentialsBaseIntent(account, authbase)
        intent.putExtra(AccountManager.KEY_ACCOUNT_AUTHENTICATOR_RESPONSE, response)

        val keyid = am.getUserData(account, KEY_KEYID).toLong()
        intent.putExtra(DarwinAuthenticatorActivity.PARAM_KEYID, keyid)

        return Bundle(1).apply { putParcelable(AccountManager.KEY_INTENT, intent) }
    }

    private fun getUpdateCredentialsBaseIntent(account: Account, authBaseUrl: String): Intent {
        val intent = Intent(context, DarwinAuthenticatorActivity::class.java)
        intent.putExtra(DarwinAuthenticatorActivity.PARAM_ACCOUNT, account)
        intent.putExtra(DarwinAuthenticatorActivity.PARAM_CONFIRM, false)
        intent.putExtra(DarwinAuthenticator.KEY_AUTH_BASE, authBaseUrl)
        return intent
    }

    @Throws(NetworkErrorException::class)
    override fun hasFeatures(response: AccountAuthenticatorResponse,
                             account: Account,
                             features: Array<String?>): Bundle {
        Log.i(TAG,
              "hasFeatures() called with: " + "response = [" + response + "], account = [" + account + "], features = " + Arrays.deepToString(
                  features))
        val hasFeature = if (features.size == 1) {
            val am = AccountManager.get(context)
            val authbase = am.getUserData(account, KEY_AUTH_BASE)
            if (authbase == null) {
                features[0] == null || DEFAULT_AUTH_BASE_URL == features[0]
            } else {
                authbase == features[0] || features[0] == null && DEFAULT_AUTH_BASE_URL == authbase
            }
        } else {
            false
        }
        return Bundle()
            .apply { putBoolean(AccountManager.KEY_BOOLEAN_RESULT, hasFeature) }
            .also { Log.i(TAG, "hasFeatures() returned: $it -> $hasFeature") }
    }

    companion object {

        /** The account type supported by the authenticator.  */
        const val ACCOUNT_TYPE = "uk.ac.bournemouth.darwin.account"
        /** The token type for darwin accounts. For now there is only this type.  */
        const val ACCOUNT_TOKEN_TYPE = "uk.ac.bournemouth.darwin.auth"
        /** The argument name used to specify the base url for authentication.  */
        const val KEY_AUTH_BASE = "authbase"

        const val DEFAULT_AUTH_BASE_URL = "https://darwin.bournemouth.ac.uk/accountmgr/"
        const val KEY_PRIVATEKEY = "privatekey"
        const val KEY_KEYID = "keyid"
        const val KEY_ACCOUNT = "account"
        private const val KEY_PUBLICKEY = "publickey"

        const val CIPHERSUITE_V2 = "RSA/ECB/PKCS1Padding"
        const val CIPHERSUITE_V1 = "RSA/NONE/NOPADDING"

        const val CHALLENGE_VERSION_V2 = "2"
        const val CHALLENGE_VERSION_V1 = "1"
        const val HEADER_CHALLENGE_VERSION = "X-Challenge-version"

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
            val newAllowedUids: String

            if (oldAllowedUids == null || oldAllowedUids.isEmpty()) {
                newAllowedUids = Integer.toString(uid)
            } else {
                if (oldAllowedUids.split(',').any { it.trim().toInt() == uid }) return

                newAllowedUids = "$oldAllowedUids,$uid"
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

        private fun encrypt(challenge: ByteArray?, privateKey: RSAPrivateKey, version: Int): ByteArray? {
            val cipher: Cipher
            try {
                cipher = Cipher.getInstance(if (version == 1) CIPHERSUITE_V1 else CIPHERSUITE_V2)
                cipher.init(Cipher.ENCRYPT_MODE, privateKey)

                return cipher.doFinal(challenge)
            } catch (e: GeneralSecurityException) {
                Log.w(TAG, e)
                return null
            }

        }

        @Throws(IOException::class)
        private fun writeResponse(conn: HttpURLConnection, response: ByteArray) {
            conn.doOutput = true
            conn.requestMethod = "POST"
            conn.setRequestProperty("Content-Type", "application/x-www-form-urlencoded;charset=utf8")
            val out = conn.outputStream
            try {
                out.write("response=".toByteArray())
                out.write(response)
            } finally {
                out.close()
            }
        }

        private fun base64encode(`in`: ByteArray?): ByteArray {
            return Base64.encode(`in`, BASE64_FLAGS)
        }

        @Throws(IOException::class, StaleCredentialsException::class)
        private fun readChallenge(account: Account, authBaseUrl: String, keyInfo: KeyInfo): ChallengeInfo? {
            val challengeUrl = URI.create(getChallengeUrl(authBaseUrl).toString() + "?keyid=" + keyInfo.keyId)
            val connection = challengeUrl.toURL().openConnection() as HttpURLConnection
            connection.instanceFollowRedirects = false// We should get the response url.
            try {
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
                if (version != 1) {
                    challengeBytes = Base64.decode(inBuffer, 0, readCount, Base64.DEFAULT)
                } else {
                    challengeBytes = Arrays.copyOf(inBuffer, readCount)
                }
                return ChallengeInfo(responseUrl, challengeBytes, version)
            } finally {
                connection.disconnect()
            }
        }

        private fun getChallengeUrl(authBaseUrl: String): URI {
            return URI.create(authBaseUrl + "challenge")
        }

        private fun getAuthBase(options: Bundle): String {
            var authBaseUrl = options.getString(KEY_AUTH_BASE)
            if (authBaseUrl == null) {
                authBaseUrl = DEFAULT_AUTH_BASE_URL
            }
            return authBaseUrl
        }

        @JvmStatic
        fun getAuthenticateUrl(authBaseUrl: String): URI {
            return URI.create(authBaseUrl + "regkey")
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
        try {
            return keyfactory.generatePrivate(keyspec) as RSAPrivateKey
        } catch (e: InvalidKeySpecException) {
            Log.w(TAG, "Could not load private key", e)
            return null
        }

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
    get() = getLong(AbstractAccountAuthenticator.KEY_CUSTOM_TOKEN_EXPIRY, -1L)
    set(value) = putLong(AbstractAccountAuthenticator.KEY_CUSTOM_TOKEN_EXPIRY, value)

private fun createResultBundle(account: Account, cookie: ByteArray): Bundle {
    return Bundle(4).apply {
        accountName = account.name
        accountType = ACCOUNT_TOKEN_TYPE
        authToken = String(cookie, UTF8)

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            customTokenExpiry =System.currentTimeMillis() + EXPIRY_TIMEOUT
        }

    }
}

fun Intent.toBundle() = Bundle(1).apply { putParcelable(AccountManager.KEY_INTENT, this) }