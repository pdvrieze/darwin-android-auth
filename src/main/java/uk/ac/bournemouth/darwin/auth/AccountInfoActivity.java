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

import android.accounts.*;
import android.app.Activity;
import android.content.Intent;
import android.os.Bundle;
import android.support.annotation.NonNull;
import android.util.Log;
import android.widget.ScrollView;
import android.widget.TextView;

import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.security.Provider;
import java.security.Provider.Service;
import java.security.Security;
import java.util.ArrayList;
import java.util.List;
import java.util.Map.Entry;
import java.util.TreeMap;


/**
 * An activity that allows some information on the account to be displayed.
 */
public class AccountInfoActivity extends Activity {

  private static final String KEY_TRYINGTOCREATEACCOUNT = "tryingToCreateAccount";
  private TextView mTextView;
  private boolean mWaitingForIntent =false;
  private boolean mTryingToCreateAccount;

  @Override
  protected void onCreate(final Bundle savedInstanceState) {
    super.onCreate(savedInstanceState);

    if (savedInstanceState!=null) {
      mTryingToCreateAccount = savedInstanceState.getBoolean(KEY_TRYINGTOCREATEACCOUNT, false);
    }

    final ScrollView scrollview = new ScrollView(this);
    mTextView = new TextView(this);
    scrollview.addView(mTextView);

    final StringBuilder text=new StringBuilder();
    {
      for (final Provider p: Security.getProviders()) {
        final TreeMap<String,List<String>> types = new TreeMap<>();
        text.append("Provider: ").append(p.getName()).append('\n');
        for(final Service service: p.getServices()) {
          final String type = service.getType();
          List<String> list = types.get(type);
          if (list==null) {
            list = new ArrayList<>();
            types.put(service.getType(), list);
          }
          list.add(service.getAlgorithm());
        }
        for(final Entry<String, List<String>> type: types.entrySet()) {
          for (final String algorithm: type.getValue()) {
            text.append("  Service type:").append(type.getKey())
            .append(" algorithm:").append(algorithm).append('\n');
          }
        }
      }
    }
    mTextView.setText(text);
    setContentView(scrollview);
  }

  @SuppressWarnings("deprecation")
  @Override
  protected void onResume() {
    super.onResume();
    final AccountManager am=AccountManager.get(this);
    final Account[] accounts = am.getAccountsByType(DarwinAuthenticator.ACCOUNT_TYPE);


    if (accounts.length>0) {
      final AccountManagerCallback<Bundle> callback = new AccountManagerCallback<Bundle>() {

        @Override
        public void run(final AccountManagerFuture<Bundle> future) {
          try {
            final Bundle result = future.getResult();
            CharSequence newText = null;
            if (result.containsKey(AccountManager.KEY_ERROR_CODE)|| result.containsKey(AccountManager.KEY_ERROR_MESSAGE)) {
              newText = "error ("+result.getString(AccountManager.KEY_ERROR_CODE)+"): "+result.getString(AccountManager.KEY_ERROR_MESSAGE);
            } else if (result.containsKey(AccountManager.KEY_INTENT)){
              if (!mWaitingForIntent) {
                newText = "received an intent";
                mWaitingForIntent =true;
                final Intent intent = result.getParcelable(AccountManager.KEY_INTENT);
                startActivity(intent);
              } else {
                mWaitingForIntent = false;
                newText="We did not receive an updated token after starting the activity";
              }
            } else if (result.containsKey(AccountManager.KEY_AUTHTOKEN)) {
              final String token = result.getString(AccountManager.KEY_AUTHTOKEN);
              if (token!=null) {
                newText = "Got an auth token: "+token;
                Log.v("ACCOUNTINFO", newText.toString());

                am.invalidateAuthToken(DarwinAuthenticator.ACCOUNT_TOKEN_TYPE, token);
              }
            }
            if (newText!=null) {
              mTextView.setText(newText);
            }
          } catch (AccountsException | IOException e) {
            reportException(e);
          }
        }
      };
      am.getAuthToken(accounts[0], DarwinAuthenticator.ACCOUNT_TOKEN_TYPE, false, callback , null);
    } else {
      if (!mTryingToCreateAccount) {
        am.addAccount(DarwinAuthenticator.ACCOUNT_TYPE, DarwinAuthenticator.ACCOUNT_TOKEN_TYPE, null, null, this, null, null);
        mTryingToCreateAccount=true;
      } else {
        mTextView.setText(R.string.lbl_account_creation_cancelled);
      }
    }
  }

  @Override
  protected void onSaveInstanceState(@NonNull final Bundle outState) {
    super.onSaveInstanceState(outState);
    outState.putBoolean(KEY_TRYINGTOCREATEACCOUNT, mTryingToCreateAccount);
  }

  private void reportException(final Throwable throwable) {
    final StringWriter writer = new StringWriter();
    throwable.printStackTrace(new PrintWriter(writer));
    mTextView.setText(getString(R.string.lbl_cancellation_exception_report, writer.toString()));
    Log.w("ACCOUNTINFO", throwable);
  }

  @Override
  protected void onPause() {
    super.onPause();
    mTextView.setText(R.string.lbl_getting_token);
  }




}
