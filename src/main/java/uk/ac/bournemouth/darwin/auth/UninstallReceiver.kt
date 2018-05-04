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

import android.accounts.AccountManager
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.util.Log
import kotlinx.coroutines.experimental.launch


/**
 * Broadcast receiver that takes care of removing package permissions for uninstalled packages.
 */
class UninstallReceiver : BroadcastReceiver() {

    override fun onReceive(context: Context, intent: Intent) {
        Log.d(TAG, "onReceive() called with: context = [$context], intent = [$intent]")
        val action = intent.action
        if (Intent.ACTION_UNINSTALL_PACKAGE == action) {
            if (BuildConfig.DEBUG) {
                val pendingResult = goAsync()
                val appContext = context.applicationContext
                launch {
                    doRemovePackagePermissions(intent, appContext)
                    pendingResult.finish()
                }
            } else {
                doRemovePackagePermissions(intent, context)
            }
        }
    }

    companion object {

        private const val TAG = "UninstallReceiver"

        private fun doRemovePackagePermissions(intent: Intent, context: Context) {
            val uninstallUid = intent.getIntExtra(Intent.EXTRA_UID, -1)
            val replacing = intent.getBooleanExtra(Intent.EXTRA_REPLACING, false)
            if (!replacing) {
                AccountManager
                    .get(context)
                    .getAccountsByType(DWN_ACCOUNT_TYPE).forEach { account ->
                    DarwinAuthenticator.removeAllowedUid(AccountManager.get(context), account, uninstallUid)
                }
            }
        }
    }
}
