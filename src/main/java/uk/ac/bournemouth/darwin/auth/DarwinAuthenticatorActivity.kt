/*
 * Copyright (c) 2016.
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
 * You should have received a copy of the GNU Lesser General Public License along with Foobar.  If not,
 * see <http://www.gnu.org/licenses/>.
 */

package uk.ac.bournemouth.darwin.auth

import android.accounts.Account
import android.accounts.AccountAuthenticatorActivity
import android.accounts.AccountAuthenticatorResponse
import android.accounts.AccountManager
import android.annotation.TargetApi
import android.app.Activity
import android.app.AlertDialog
import android.app.AlertDialog.Builder
import android.app.Dialog
import android.content.Context
import android.content.Intent
import android.databinding.DataBindingUtil
import android.net.Uri
import android.os.AsyncTask
import android.os.Build
import android.os.Bundle
import android.util.Base64
import android.util.Log
import android.view.KeyEvent
import android.view.View
import android.view.View.OnClickListener
import android.view.inputmethod.EditorInfo
import android.widget.EditText
import android.widget.TextView
import android.widget.TextView.OnEditorActionListener
import android.widget.Toast
import uk.ac.bournemouth.darwin.auth.databinding.DarwinAuthenticatorActivityBinding
import java.io.*
import java.lang.ref.WeakReference
import java.net.HttpURLConnection
import java.net.MalformedURLException
import java.net.URLEncoder
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey
import java.util.concurrent.Callable
import java.util.concurrent.ExecutionException
import java.util.concurrent.Future
import java.util.concurrent.FutureTask


/**
 * The activity that takes care of actually providing a darwin login dialog.
 */
class DarwinAuthenticatorActivity : AccountAuthenticatorActivity(), OnClickListener, OnEditorActionListener {

    private var keyId = -1L
    private var isConfirmCredentials: Boolean = false
    private var authTask: AuthenticatorTask? = null
    @Suppress("DEPRECATION")
    private var progressDialog: android.app.ProgressDialog? = null
    private lateinit var accountManager: AccountManager
    private var keypair: Future<KeyPair>? = null
    private lateinit var binding: DarwinAuthenticatorActivityBinding

    private var account: Account? = null
    private var authenticatorResponse: AccountAuthenticatorResponse? = null

    private enum class AuthResult {
        CANCELLED,
        SUCCESS,
        INVALID_CREDENTIALS,
        UNKNOWNFAILURE
    }

    @TargetApi(23)
    private object API23Helper {
        fun notifyAccountAuthenticated(accountManager: AccountManager, account: Account?) {
            accountManager.notifyAccountAuthenticated(account)
        }
    }

    /**
     * A task that takes care of actually authenticating the user.
     */
    private class AuthenticatorTask(activity: DarwinAuthenticatorActivity) : AsyncTask<Any, CharSequence, AuthResult>() {

        private val _activity = WeakReference<DarwinAuthenticatorActivity>(activity)
        private val activity: DarwinAuthenticatorActivity?
            get() = _activity.get()

        private lateinit var account: Account

        override fun doInBackground(vararg params: Any): AuthResult {
            account = params[0] as Account

            val aUsername = account.getUsername()
            val password = params[1] as String
            var keypair: KeyPair? = null
            run {
                val ac = activity ?: return AuthResult.CANCELLED
                val isConfirm = ac.isConfirmCredentials
                if (!isConfirm) {

                    publishProgress(ac.getText(R.string.creating_keys))
                    try {
                        // The keypair generation is initiated on start of the activity, so it can happen while the details are entered.
                        keypair = ac.keypair!!.get()
                    } catch (e: InterruptedException) {
                        return if (isCancelled) {
                            AuthResult.CANCELLED
                        } else {
                            AuthResult.UNKNOWNFAILURE
                        }
                    } catch (e: ExecutionException) {
                        Log.w(TAG, "Getting keypair failed", e.cause)
                        return AuthResult.UNKNOWNFAILURE
                    }

                    if (isCancelled) {
                        return AuthResult.CANCELLED
                    }
                }
            }
            activity?.apply {
                publishProgress(getText(R.string.authenticating))
                assert(keypair != null)
                val authResult = registerPublicKey(binding.authBaseUrl, aUsername, password,
                                                   keypair!!.public as RSAPublicKey)
                if (authResult != AuthResult.SUCCESS) {
                    return authResult
                }
                return if (isCancelled) AuthResult.CANCELLED else AuthResult.SUCCESS
            }
            return AuthResult.CANCELLED
        }

        override fun onPostExecute(result: AuthResult) {
            activity?.run {
                Log.i(TAG, "Authentication result: " + result.toString())
                if (progressDialog != null) {
                    progressDialog!!.dismiss()
                }
                val account = this@AuthenticatorTask.account
                when (result) {
                    DarwinAuthenticatorActivity.AuthResult.SUCCESS             -> {
                        try {
                            storeCredentials(account, keyId, keypair!!.get(), binding.authBaseUrl)
                        } catch (e: InterruptedException) {
                            Log.e(TAG, "Retrieving keypair a second time failed. Should never happen.", e)
                        } catch (e: ExecutionException) {
                            Log.e(TAG, "Retrieving keypair a second time failed. Should never happen.", e)
                        }

                        val msgId: Int = if (isConfirmCredentials) R.string.toast_update_success else R.string.toast_create_success
                        val toast = Toast.makeText(this@run, msgId, Toast.LENGTH_SHORT)
                        notifyAccountAuthenticated(accountManager, account)

                        val intent = Intent().apply {
                            putExtra(AccountManager.KEY_ACCOUNT_NAME, account.name)
                            putExtra(AccountManager.KEY_ACCOUNT_TYPE, DWN_ACCOUNT_TYPE)
                            setAccountAuthenticatorResult(extras)
                        }
                        setResult(Activity.RESULT_OK, intent)
                        toast.show()
                        finish()
                    }
                    DarwinAuthenticatorActivity.AuthResult.CANCELLED           -> {
                        val toast = Toast.makeText(this@run, R.string.toast_cancelled,
                                                   Toast.LENGTH_SHORT)
                        toast.show()
                        finish()
                    }
                    DarwinAuthenticatorActivity.AuthResult.UNKNOWNFAILURE      -> {
                        @Suppress("DEPRECATION")
                        showDialog(DLG_ERROR)
                    }
                    DarwinAuthenticatorActivity.AuthResult.INVALID_CREDENTIALS -> {
                        @Suppress("DEPRECATION")
                        showDialog(DLG_INVALIDAUTH)
                    }
                }
            }
        }

        override fun onProgressUpdate(vararg values: CharSequence) {
            activity?.apply {
                progressDialog?.setMessage(values[0])
            }
            Log.i(TAG, "Auth progress: " + values[0])
        }

    }

    override fun onCreate(icicle: Bundle?) {
        super.onCreate(icicle)
        PRNGFixes.ensureApplied()

        binding = DataBindingUtil.setContentView(this, R.layout.get_password)

        if (icicle != null) {
            account = icicle.account
            with(binding) {
                username = account?.getUsername() ?: icicle.username

                usernameLocked = icicle.lockedUsername

                password = icicle.password
                authBaseUrl = icicle.authBase
            }

            isConfirmCredentials = icicle.isConfirm
            keyId = icicle.keyid
            authenticatorResponse = icicle.authenticatorResponse
        } else {
            account = intent.account
            with(binding) {
                val uname = account?.getUsername() ?: intent.username

                username = uname
                usernameLocked = !uname.isNullOrEmpty()
                authBaseUrl = intent.authBase
            }
            isConfirmCredentials = intent.isConfirm
            keyId = intent.keyid
            authenticatorResponse = intent.authenticatorResponse
        }
        accountManager = AccountManager.get(this)

        if (account != null) {
            accountManager.getUserData(account, PARAM_KEYID)?.toLongOrNull()?.let { keyId = it }
        }

        binding.editPassword.setOnEditorActionListener(this)



        binding.cancelbutton.setOnClickListener(this)
        binding.okbutton.setOnClickListener(this)

        if (!isConfirmCredentials) {
            keypair = generateKeys()
        }
    }

    private fun generateKeys(): Future<KeyPair> {
        synchronized(this) {
            keypair?.let { keypair ->
                try {
                    if (keypair.isCancelled || keypair.isDone && keypair.get() == null) {
                        this.keypair = null // Remove the previous pair
                    } else {
                        return keypair // We're still in progress, just bail out.
                    }
                } catch (e: InterruptedException) {
                    this.keypair = null
                } catch (e: ExecutionException) {
                    this.keypair = null
                    Log.w(TAG, "Error generating keys", e)
                }

            }
        }

        val future = FutureTask(Callable<KeyPair> {
            Log.i(TAG, "Generating a pair of RSA keys")
            KeyPairGenerator.getInstance(DarwinAuthenticator.KEY_ALGORITHM).run {
                initialize(KEY_SIZE)
                generateKeyPair()
            }
        })

        Thread(future).start()

        return future
    }

    override fun onSaveInstanceState(outState: Bundle) {
        outState.also {
            it.username = binding.editUsername.text?.toString()
            it.password = binding.editPassword.text?.toString()
            it.isConfirm = isConfirmCredentials
            it.lockedUsername = binding.usernameLocked
            it.authBase = binding.authBaseUrl ?: DarwinAuthenticator.DEFAULT_AUTH_BASE_URL
            it.account = account
            it.keyid = keyId
        }
    }

    override fun onStop() {
        // No need to waste effort on generating a keypair we don't use.
        synchronized(this) {
            if (keypair != null && !keypair!!.isDone) {
                keypair!!.cancel(true)
            }
        }
        super.onStop()
    }

    @Suppress("OverridingDeprecatedMember")
    override fun onCreateDialog(id: Int, args: Bundle?): Dialog? = when (id) {
        DLG_PROGRESS    -> {
            createProcessDialog()
        }
        DLG_ERROR       -> {
            createErrorDialog()
        }
        DLG_INVALIDAUTH -> {
            createInvalidAuthDialog()
        }
        else            -> null
    }

    private fun createErrorDialog(): Dialog {
        val builder = createRetryDialogBuilder()
        return builder.setMessage(R.string.dlg_msg_error).setTitle(R.string.dlg_title_error).create()
    }

    private fun createInvalidAuthDialog(): Dialog {
        val builder = createRetryDialogBuilder()
        return builder.setMessage(R.string.dlg_msg_unauth).setTitle(R.string.dlg_title_unauth).create()
    }

    private fun createRetryDialogBuilder(): Builder {
        val builder = AlertDialog.Builder(this)
        builder.setCancelable(true).setNegativeButton(android.R.string.cancel) { dialog, _ ->
            cancelClicked()
            dialog.dismiss()
        }.setNeutralButton(R.string.retry) { dialog, _ ->
            retryClicked()
            dialog.dismiss()
        }
        return builder
    }

    private fun createProcessDialog(): Dialog {
        @Suppress("DEPRECATION")
        val dialog = android.app.ProgressDialog(this)
        dialog.setMessage(getText(R.string.authenticating))
        dialog.isIndeterminate = true
        dialog.setCancelable(true)
        dialog.setCanceledOnTouchOutside(false)
        dialog.setOnCancelListener {
            Log.i(TAG, "user cancelling authentication")
            if (authTask != null) {
                authTask!!.cancel(true)
            }
        }
        // We save off the progress dialog in a field so that we can dismiss
        // it later. We can't just call dismissDialog(0) because the system
        // can lose track of our dialog if there's an orientation change.
        progressDialog = dialog
        return dialog
    }

    override fun onEditorAction(textView: TextView, actionId: Int, event: KeyEvent): Boolean {
        if (textView.id != R.id.editPassword) {
            return false
        }
        when (actionId) {
            EditorInfo.IME_NULL, EditorInfo.IME_ACTION_DONE, EditorInfo.IME_ACTION_GO -> {
                startAuthentication()
                return true
            }
        }
        return false
    }

    /**
     * Handle the creation of an account.
     */
    private fun startAuthentication() {
        val username = (findViewById<View>(R.id.editUsername) as EditText).text.toString()
        val password = (findViewById<View>(R.id.editPassword) as EditText).text.toString()
        val authTask = AuthenticatorTask(this).also { authTask = it }
        @Suppress("DEPRECATION")
        showDialog(DLG_PROGRESS)
        if (!isConfirmCredentials) {
            keypair = generateKeys() // Just call again, just to be sure.
        }

        val accountName = getAccountName(username)
        val currentAccount = this.account
        val account = if (currentAccount?.name == accountName) {
            currentAccount
        } else {
            Account(accountName, DWN_ACCOUNT_TYPE)
        }
        authTask.execute(account, password)

    }

    private fun getAccountName(username: String): String {
        val accountName: String
        val authBaseUrl = binding.authBaseUrl?.let { if (it.isEmpty()) null else it }
                          ?: DarwinAuthenticator.DEFAULT_AUTH_BASE_URL
        accountName = when {
            (authBaseUrl == DarwinAuthenticator.DEFAULT_AUTH_BASE_URL) && username.indexOf('@') < 0
                 -> username

            else -> "$username@${Uri.parse(authBaseUrl).host.toLowerCase()}"
        }
        return accountName
    }

    override fun onClick(v: View) {
        when (v.id) {
            R.id.cancelbutton -> cancelClicked()
            R.id.okbutton     -> startAuthentication()
        }
    }

    private fun cancelClicked() {
        finish()
    }

    private fun retryClicked() {
        val usernameEdit = findViewById<View>(R.id.editUsername) as EditText
        val passwordEdit = findViewById<View>(R.id.editPassword) as EditText
        passwordEdit.setText("")
        usernameEdit.requestFocus()
    }

    /** Try to authenticate by registering the public key to the server.  */
    private fun registerPublicKey(authBaseUrl: String?,
                                  username: String,
                                  password: String,
                                  publicKey: RSAPublicKey): AuthResult {
        val encodedPublicKey = DarwinAuthenticator.encodePublicKey(publicKey)
        Log.d(TAG, "registering encoded public key at id ($keyId):$encodedPublicKey")
        Log.d(TAG, "public exp:" + Base64.encodeToString(publicKey.publicExponent.toByteArray(), 0))
        Log.d(TAG, "public mod:" + Base64.encodeToString(publicKey.modulus.toByteArray(), 0))
        val conn: HttpURLConnection
        try {
            conn = DarwinAuthenticator.getAuthenticateUrl(authBaseUrl).toURL().openConnection() as HttpURLConnection
            try {
                conn.requestMethod = "POST"
                conn.doOutput = true
                conn.setRequestProperty("Content-Type", "application/x-www-form-urlencoded;charset=utf8")

                OutputStreamWriter(conn.outputStream, UTF8).use {
                    BufferedWriter(it).use { out ->
                        out.append("username=").append(URLEncoder.encode(username, UTF8.name()))
                        out.append("&password=").append(URLEncoder.encode(password, UTF8.name()))
                        out.append("&app=").append(URLEncoder.encode(appName, UTF8.name()))
                        out.append("&pubkey=").append(encodedPublicKey)
                        if (keyId >= 0) out.append("&id=").append(keyId.toString())
                    }
                }

                val response = conn.responseCode
                Log.i(TAG, "Authentication response code: $response")
                if (response == HttpURLConnection.HTTP_FORBIDDEN) {
                    return AuthResult.INVALID_CREDENTIALS
                } else if (response in 200..399) {
                    InputStreamReader(conn.inputStream, UTF8).useLines { lines ->
                        lines.forEach { line ->
                            val p = line.indexOf(':')
                            if (p >= 0 && "key" == line.substring(0, p).trim { it <= ' ' }) {
                                keyId = java.lang.Long.parseLong(line.substring(p + 1).trim { it <= ' ' })
                            }
                        }
                    }
                    if (keyId >= 0) return AuthResult.SUCCESS
                } else {
                    logStream(conn.errorStream)
                }
            } finally {
                conn.disconnect()
            }
            return AuthResult.UNKNOWNFAILURE
        } catch (e: MalformedURLException) {
            Log.e(TAG, "Should never happen", e)
            return AuthResult.UNKNOWNFAILURE
        } catch (e: IOException) {
            Log.d(TAG, "Failure registering keys", e)
            return AuthResult.UNKNOWNFAILURE
        }

    }

    /**
     * Record they private key and username to the account manager.
     *
     * @param account  The account for the account manager
     * @param keyId    The id of the key involved.
     * @param keyPair  The actual keypair to record for this user.
     * @param authbase The url that is the basis for this authentication. One authenticator can support multiple bases with
     */
    private fun storeCredentials(account: Account, keyId: Long, keyPair: KeyPair, authbase: String?) {
        val realAuthbase = if (authbase.isNullOrEmpty()) DarwinAuthenticator.DEFAULT_AUTH_BASE_URL else authbase
        val keyspec = DarwinAuthenticator.encodePrivateKey(keyPair.private as RSAPrivateKey)
        val accountManager = this.accountManager

        var updateUser = binding.usernameLocked
        if (!updateUser) {
            val bundle = Bundle(3)
            bundle.putString(DarwinAuthenticator.KEY_PRIVATEKEY, keyspec)
            bundle.putString(DarwinAuthenticator.KEY_KEYID, java.lang.Long.toString(keyId))
            bundle.putString(DarwinAuthenticator.KEY_AUTH_BASE, realAuthbase)
            updateUser = !accountManager.addAccountExplicitly(account, null, bundle)
        }

        if (updateUser) {
            accountManager.setUserData(account, DarwinAuthenticator.KEY_PRIVATEKEY, keyspec)
            accountManager.setUserData(account, DarwinAuthenticator.KEY_KEYID, java.lang.Long.toString(keyId))
            accountManager.setUserData(account, DarwinAuthenticator.KEY_AUTH_BASE, realAuthbase)
        }
    }

    companion object {

        private fun notifyAccountAuthenticated(accountManager: AccountManager?, account: Account?) {
            if (Build.VERSION.SDK_INT >= 23) {
                API23Helper.notifyAccountAuthenticated(accountManager!!, account)
            }
        }

        private const val KEY_SIZE = 2048
        private val TAG = DarwinAuthenticatorActivity::class.java.name
        private const val DLG_PROGRESS = 0
        private const val DLG_ERROR = 1
        private const val DLG_INVALIDAUTH = 2

        private fun Account.getUsername(): String {
            val i = name.lastIndexOf('@')
            return when {
                i >= 0 -> name.substring(0, i)
                else   -> name
            }
        }

        private val appName: String
            get() = when {
                Build.MODEL.contains(Build.MANUFACTURER) -> "DarwinAuthenticator on ${Build.MODEL}"
                else                                     -> "DarwinAuthenticator on ${Build.MANUFACTURER} ${Build.MODEL}"
            }

        @Throws(IOException::class)
        private fun logStream(errorStream: InputStream) {
            Log.d(TAG, "Authentication error response: ")
            InputStreamReader(errorStream).useLines { line ->
                Log.d(TAG, "> $line")
            }
        }

    }

}

/** [Account] -  The account involved in the authentication.  */
const val PARAM_ACCOUNT = "account"

private var Bundle.account: Account?
    get() = getParcelable(PARAM_ACCOUNT)
    set(value) = putParcelable(PARAM_ACCOUNT, value)

private val Intent.account: Account?
    get() = getParcelableExtra(PARAM_ACCOUNT)

/** [String] - The user name  */
const val PARAM_USERNAME = "username"

private var Bundle.username: String?
    get() = getString(PARAM_USERNAME)
    set(value) = putString(PARAM_USERNAME, value)

private val Intent.username: String?
    get() = getStringExtra(PARAM_USERNAME)

/** [Boolean] - The username should not be editable.  */
const val PARAM_LOCK_USERNAME = "lockedUsername"

private var Bundle.lockedUsername: Boolean
    get() = getBoolean(PARAM_LOCK_USERNAME, false)
    set(value) = putBoolean(PARAM_LOCK_USERNAME, value)

/** [Boolean] - Indicate that this is not a login, but a confirmation.  */
const val PARAM_CONFIRM = "confirm"

private var Bundle.isConfirm: Boolean
    get() = getBoolean(PARAM_CONFIRM, false)
    set(value) = putBoolean(PARAM_CONFIRM, value)

private val Intent.isConfirm: Boolean
    get() = getBooleanExtra(PARAM_CONFIRM, false)

private val Intent.authBase
    get() = getStringExtra(DarwinAuthenticator.KEY_AUTH_BASE) ?: DarwinAuthenticator.DEFAULT_AUTH_BASE_URL

fun Context.darwinAuthenticatorActivity(account: Account?,
                                        authbase: String,
                                        isConfirm: Boolean = false,
                                        keyid: Long = -1L,
                                        response: AccountAuthenticatorResponse? = null) =
    Intent(this, DarwinAuthenticatorActivity::class.java).apply {
        putExtra(PARAM_ACCOUNT, account)
        putExtra(DarwinAuthenticator.KEY_AUTH_BASE, authbase)
        putExtra(PARAM_CONFIRM, isConfirm)
        if (keyid >= 0L) putExtra(PARAM_KEYID, keyid)
        response?.let { putExtra(AccountManager.KEY_ACCOUNT_AUTHENTICATOR_RESPONSE, response) }
    }

var Bundle.authenticatorResponse: AccountAuthenticatorResponse?
    get() = getParcelable(AccountManager.KEY_ACCOUNT_AUTHENTICATOR_RESPONSE)
    set(value) = putParcelable(AccountManager.KEY_ACCOUNT_AUTHENTICATOR_RESPONSE, value)

private val Intent.authenticatorResponse
    get(): AccountAuthenticatorResponse? = getParcelableExtra(AccountManager.KEY_ACCOUNT_AUTHENTICATOR_RESPONSE)

/** [Boolean] - The initialisation value for the password.  */
const val PARAM_PASSWORD = "password"

var Bundle.password
    get():String? = getString(PARAM_PASSWORD)
    set(value) = putString(PARAM_PASSWORD, value)

/** [Long] - The id of the key. The server supports multiple ids to be registered.  */
const val PARAM_KEYID = "keyid"

private val Intent.keyid get() = getLongExtra(PARAM_KEYID, -1L)

var Bundle.keyid: Long
    get() = getLong(PARAM_KEYID, -1L)
    set(value) = if (value >= 0) putLong(PARAM_KEYID, value) else remove(PARAM_KEYID)