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
import android.app.Activity
import android.os.Bundle
import android.util.Log
import android.widget.ScrollView
import android.widget.TextView
import kotlinx.coroutines.experimental.android.UI
import kotlinx.coroutines.experimental.launch
import nl.adaptivity.android.coroutines.Maybe
import nl.adaptivity.android.coroutines.activityResult
import nl.adaptivity.android.coroutines.getAuthToken

import java.io.PrintWriter
import java.io.StringWriter
import java.security.Security
import java.util.TreeMap


/**
 * An activity that allows some information on the account to be displayed.
 */
class AccountInfoActivity : Activity() {
    private lateinit var textView: TextView
    private var isWaitingForIntent = false
    private var isTryingToCreateAccount: Boolean = false

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        if (savedInstanceState != null) {
            isTryingToCreateAccount = savedInstanceState.tryingToCreateAccount
        }

        textView = TextView(this)
        setContentView(ScrollView(this).apply { addView(textView) })

        val text = buildString {
            val text = this
            for (p in Security.getProviders()) {
                val types = TreeMap<String, MutableList<String>>()
                text.append("Provider: ").append(p.getName()).append('\n')
                p.services.forEach { service ->
                    val type = service.type
                    val list = types.getOrPut(type) { mutableListOf() }
                    list.add(service.algorithm)
                }

                for (type in types.entries) {
                    for (algorithm in type.value) {
                        text.append("  Service type:").append(type.key)
                            .append(" algorithm:").append(algorithm).append('\n')
                    }
                }
            }
        }
        textView.text = text
    }

    override fun onResume() {
        super.onResume()

        launch {
            val am = AccountManager.get(this@AccountInfoActivity)
            val accounts = am.getAccountsByType(DarwinAuthenticator.ACCOUNT_TYPE)
            if (accounts.isNotEmpty()) {
                val token = am.getAuthToken(this@AccountInfoActivity, accounts[0],
                                            DarwinAuthenticator.ACCOUNT_TOKEN_TYPE)
                if (token != null) {
                    val newText = "Got an auth token: " + token
                    Log.v("ACCOUNTINFO", newText)

                    am.invalidateAuthToken(DarwinAuthenticator.ACCOUNT_TOKEN_TYPE, token)
                    launch(UI) { textView.text = newText }
                }
            } else {
                if (!isTryingToCreateAccount) {
                    val intent = AccountManager.newChooseAccountIntent(null,
                                                                       null,
                                                                       arrayOf(DarwinAuthenticator.ACCOUNT_TYPE), null,
                                                                       DarwinAuthenticator.ACCOUNT_TOKEN_TYPE,
                                                                       emptyArray(),
                                                                       null)
                    when (activityResult(intent)) {
                        is Maybe.Cancelled -> launch(UI) { textView.setText(R.string.lbl_account_creation_cancelled) }
                        else               -> Unit
                    }
                    isTryingToCreateAccount = true
                } else {
                    launch(UI) { textView.setText(R.string.lbl_account_creation_cancelled) }
                }
            }
            Unit

        }
    }

    override fun onSaveInstanceState(outState: Bundle) {
        super.onSaveInstanceState(outState)
        outState.tryingToCreateAccount = isTryingToCreateAccount
    }

    private fun reportException(throwable: Throwable) {
        val writer = StringWriter()
        throwable.printStackTrace(PrintWriter(writer))
        textView.setText(getString(R.string.lbl_cancellation_exception_report, writer.toString()))
        Log.w("ACCOUNTINFO", throwable)
    }

    override fun onPause() {
        super.onPause()
        textView.setText(R.string.lbl_getting_token)
    }

    companion object {

        var Bundle.tryingToCreateAccount
            get() = getBoolean("tryingToCreateAccount", false)
            set(value) = putBoolean("tryingToCreateAccount", value)
    }


}
