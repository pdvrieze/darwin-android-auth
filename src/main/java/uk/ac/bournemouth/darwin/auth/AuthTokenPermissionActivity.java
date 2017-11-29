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
import android.app.Activity;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.PackageManager.NameNotFoundException;
import android.databinding.DataBindingUtil;
import android.os.Bundle;
import android.util.Log;
import android.view.View;
import android.view.View.OnClickListener;
import uk.ac.bournemouth.darwin.auth.databinding.GetPermissionBinding;


/**
 * Activity for permitting access to the darwin token.
 */
public class AuthTokenPermissionActivity extends Activity implements OnClickListener {

  private static final String TAG = "AuthTokenPermissionAct";

  GetPermissionBinding mBinding;
  private int mCallerUid;

  @Override
  protected void onCreate(final Bundle savedInstanceState) {
    super.onCreate(savedInstanceState);
    mBinding = DataBindingUtil.setContentView(this, R.layout.get_permission);
    mBinding.setAccount(getIntent().<Account>getParcelableExtra(DarwinAuthenticator.KEY_ACCOUNT));
    mCallerUid = getIntent().getIntExtra(AccountManager.KEY_CALLER_UID, -1);
    final PackageManager pm            = getPackageManager();
    final String         callerPackage = pm.getPackagesForUid(mCallerUid)[0];
    String               packageName;
    try {
      final PackageInfo packageInfo = pm.getPackageInfo(callerPackage, 0);
      final int         labelRes    = packageInfo.applicationInfo.labelRes;
      packageName = pm.getResourcesForApplication(packageInfo.applicationInfo).getString(labelRes);
    } catch (NameNotFoundException e) {
      Log.w(TAG, "onCreate: ", e);
      packageName = callerPackage;
    }

    mBinding.setCallerName(packageName);
    mBinding.cancelbutton.setOnClickListener(this);
    mBinding.okbutton.setOnClickListener(this);
  }

  @Override
  public void onClick(final View v) {
    switch (v.getId()) {
      case R.id.okbutton:
        DarwinAuthenticator.addAllowedUid(AccountManager.get(this), mBinding.getAccount(), mCallerUid);
        // fall-through
      case R.id.cancelbutton:
        finish();
    }
  }

}
