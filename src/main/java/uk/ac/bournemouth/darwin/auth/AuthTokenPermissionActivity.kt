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

import android.accounts.Account
import android.accounts.AccountManager
import android.app.Activity
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager.NameNotFoundException
import android.databinding.DataBindingUtil
import android.os.Bundle
import android.util.Log
import android.view.View
import android.view.View.OnClickListener
import uk.ac.bournemouth.darwin.auth.databinding.GetPermissionBinding


/**
 * Activity for permitting access to the darwin token.
 */
class AuthTokenPermissionActivity : Activity(), OnClickListener {

    private lateinit var binding: GetPermissionBinding
    private var callerUid: Int = 0

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = DataBindingUtil.setContentView(this, R.layout.get_permission)
        binding.account = intent.account
        callerUid = intent.callerUid

        val pm = packageManager
        val packageName = intent.packageName?: pm.getPackagesForUid(callerUid)?.get(0)
        val packageLabel: String =
        try {
            val packageInfo = pm.getPackageInfo(packageName, 0)
            val labelRes = packageInfo.applicationInfo.labelRes
            pm.getResourcesForApplication(packageInfo.applicationInfo).getString(labelRes)
        } catch (e: NameNotFoundException) {
            Log.w(TAG, "onCreate: ", e)
            packageName ?: "<MISSING PACKAGE, UNSAFE>".also {
                binding.okbutton.isEnabled = false
            }
        }

        binding.callerName = "$packageName:\n  $packageLabel"
        binding.cancelbutton.setOnClickListener(this)
        binding.okbutton.setOnClickListener(this)
    }

    override fun onClick(v: View) {
        when (v.id) {
            R.id.okbutton     -> {
                DarwinAuthenticator.addAllowedUid(AccountManager.get(this), binding.account!!, callerUid)
                finish()
            }
        // fall-through
            R.id.cancelbutton -> finish()
        }
    }

    companion object {
        private val Intent.account: Account? get() = getParcelableExtra(DarwinAuthenticator.KEY_ACCOUNT)
        private val Intent.callerUid: Int get() = getIntExtra(AccountManager.KEY_CALLER_UID, -1)
        private val Intent.packageName:String? get() = getStringExtra(AccountManager.KEY_ANDROID_PACKAGE_NAME)

        private const val TAG = "AuthTokenPermissionAct"
    }

}

fun Context.authTokenPermissionActivity(account: Account, callerUid: Int, packageName: String?): Intent {
    return Intent(this, AuthTokenPermissionActivity::class.java).apply {
        putExtra(DarwinAuthenticator.KEY_ACCOUNT, account)
        putExtra(AccountManager.KEY_CALLER_UID, callerUid)
        packageName?.let { putExtra(AccountManager.KEY_ANDROID_PACKAGE_NAME, it) }
    }
}
