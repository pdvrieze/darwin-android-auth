package uk.ac.bournemouth.darwin.auth;

import java.io.IOException;
import java.security.Provider;
import java.security.Provider.Service;
import java.security.Security;
import java.util.ArrayList;
import java.util.List;
import java.util.Map.Entry;
import java.util.TreeMap;

import android.accounts.*;
import android.app.Activity;
import android.os.Bundle;
import android.util.Log;
import android.widget.ScrollView;
import android.widget.TextView;


public class AccountInfoActivity extends Activity {

  private TextView aTextView;

  @Override
  protected void onCreate(Bundle pSavedInstanceState) {
    super.onCreate(pSavedInstanceState);
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
            final String token = pFuture.getResult().getString(AccountManager.KEY_AUTHTOKEN);
            if (token!=null) {
              Log.v("ACCOUNTINFO", "Got an authtoken: "+token);
              aTextView.setText("Got an auth token: "+token);
//            AccountManager am = AccountManager.get(AccountInfoActivity.this);
              am.invalidateAuthToken(DarwinAuthenticator.ACCOUNT_TOKEN_TYPE, token);
            }
          } catch (OperationCanceledException e) {
            Log.w("ACCOUNTINFO", e);
          } catch (AuthenticatorException e) {
            Log.w("ACCOUNTINFO", e);
          } catch (IOException e) {
            Log.w("ACCOUNTINFO", e);
          }
        }
      };
      am.getAuthToken(accounts[0], DarwinAuthenticator.ACCOUNT_TOKEN_TYPE, false, callback , null);
    } else {
      am.addAccount(DarwinAuthenticator.ACCOUNT_TYPE, DarwinAuthenticator.ACCOUNT_TOKEN_TYPE, null, null, this, null, null);
    }
  }
  
  protected void onPause() {
    super.onPause();
    aTextView.setText("Getting auth token");
  }
  
  
  

}
