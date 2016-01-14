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

package uk.ac.bournemouth.darwin.auth;

import android.accounts.Account;
import android.accounts.AccountManager;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.os.AsyncTask;
import android.os.Debug;
import android.util.Log;


/**
 * Created by pdvrieze on 13/01/16.
 */
public class UninstallReceiver extends BroadcastReceiver {

  private static final String TAG = "UninstallReceiver";

  @Override
  public void onReceive(final Context context, final Intent intent) {
    Log.d(TAG, "onReceive() called with: " + "context = [" + context + "], intent = [" + intent + "]");
    if (BuildConfig.DEBUG) {
      (new AsyncTask<PendingResult, Void, PendingResult>() {
        @Override
        protected PendingResult doInBackground(final PendingResult[] params) {
          Debug.waitForDebugger();
          doRemovePackagePermissions(intent, context);

          return params[0];
        }

        @Override
        protected void onPostExecute(final PendingResult pendingResult) {
          pendingResult.finish();
        }
      }).execute(goAsync());
    } else {
      doRemovePackagePermissions(intent, context);
    }
            ;
  }

  private void doRemovePackagePermissions(final Intent intent, final Context context) {
    int uninstallUid = intent.getIntExtra(Intent.EXTRA_UID, -1);
    boolean replacing = intent.getBooleanExtra(Intent.EXTRA_REPLACING, false);
    if (! replacing) {
      AccountManager am = AccountManager.get(context);
      Account[] accounts = am.getAccountsByType(DarwinAuthenticator.ACCOUNT_TYPE);
      for(Account account:accounts) {
        DarwinAuthenticator.removeAllowedUid(am, account, uninstallUid);
      }
    }
  }
}
