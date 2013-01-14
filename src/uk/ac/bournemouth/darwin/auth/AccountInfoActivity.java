package uk.ac.bournemouth.darwin.auth;

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

import android.accounts.*;
import android.app.Activity;
import android.content.Intent;
import android.os.Bundle;
import android.util.Log;
import android.widget.ScrollView;
import android.widget.TextView;


public class AccountInfoActivity extends Activity {

  private static final String KEY_TRYINGTOCREATEACCOUNT = "tryingToCreateAccount";
  private TextView aTextView;
  private boolean aWaitingForIntent=false;
  private boolean mTryingToCreateAccount;

  @Override
  protected void onCreate(Bundle pSavedInstanceState) {
    super.onCreate(pSavedInstanceState);

    if (pSavedInstanceState!=null) {
      mTryingToCreateAccount = pSavedInstanceState.getBoolean(KEY_TRYINGTOCREATEACCOUNT, false);
    }

    ScrollView scrollview = new ScrollView(this);
    aTextView = new TextView(this);
    scrollview.addView(aTextView);

    StringBuilder text=new StringBuilder();
    {
      for (Provider p: Security.getProviders()) {
        TreeMap<String,List<String>> types = new TreeMap<String, List<String>>();
        text.append("Provider: ").append(p.getName()).append('\n');
        for(Service s: p.getServices()) {
          final String type = s.getType();
          List<String> list = types.get(type);
          if (list==null) {
            list = new ArrayList<String>();
            types.put(s.getType(), list);
          }
          list.add(s.getAlgorithm());
        }
        for(Entry<String, List<String>> type: types.entrySet()) {
          for (String algorithm: type.getValue()) {
            text.append("  Service type:").append(type.getKey())
            .append(" algorithm:").append(algorithm).append('\n');
          }
        }
      }
    }
    aTextView.setText(text);
    setContentView(scrollview);
  }

  @SuppressWarnings("deprecation")
  @Override
  protected void onResume() {
    super.onResume();
    final AccountManager am=AccountManager.get(this);
    Account[] accounts = am.getAccountsByType(DarwinAuthenticator.ACCOUNT_TYPE);


    if (accounts.length>0) {
      AccountManagerCallback<Bundle> callback = new AccountManagerCallback<Bundle>() {

        @Override
        public void run(AccountManagerFuture<Bundle> pFuture) {
          try {
            final Bundle result = pFuture.getResult();
            CharSequence newText = null;
            if (result.containsKey(AccountManager.KEY_ERROR_CODE)|| result.containsKey(AccountManager.KEY_ERROR_MESSAGE)) {
              newText = "error ("+result.getString(AccountManager.KEY_ERROR_CODE)+"): "+result.getString(AccountManager.KEY_ERROR_MESSAGE);
            } else if (result.containsKey(AccountManager.KEY_INTENT)){
              if (! aWaitingForIntent) {
                newText = "received an intent";
                aWaitingForIntent=true;
                Intent intent = result.getParcelable(AccountManager.KEY_INTENT);
                startActivity(intent);
              } else {
                aWaitingForIntent = false;
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
              aTextView.setText(newText);
            }
          } catch (AccountsException e) {
            Throwable cause = e.getCause();
            reportException(e);
          } catch (IOException e) {
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
        aTextView.setText("Account creation cancelled");
      }
    }
  }

  @Override
  protected void onSaveInstanceState(Bundle pOutState) {
    super.onSaveInstanceState(pOutState);
    pOutState.putBoolean(KEY_TRYINGTOCREATEACCOUNT, mTryingToCreateAccount);
  }

  private void reportException(Throwable pThrowable) {
    StringWriter writer = new StringWriter();
//    boolean first = true;
//    for(Throwable throwable = pThrowable; throwable!=null; throwable = throwable.getCause()) {
//      if (first) {
//        first = false;
//      } else {
//        writer.write("Caused by:\n");
//      }
//      throwable.printStackTrace(new PrintWriter(writer));
//    }
    pThrowable.printStackTrace(new PrintWriter(writer));
    aTextView.setText("Cancelled: "+writer.toString());
    Log.w("ACCOUNTINFO", pThrowable);
  }

  @Override
  protected void onPause() {
    super.onPause();
    aTextView.setText("Getting auth token");
  }




}
