package uk.ac.bournemouth.darwin.auth;

import java.io.IOException;

import android.accounts.*;
import android.app.Activity;
import android.os.Bundle;
import android.util.Log;
import android.widget.TextView;


public class AccountInfoActivity extends Activity {

  @Override
  protected void onCreate(Bundle pSavedInstanceState) {
    super.onCreate(pSavedInstanceState);
    TextView tv=new TextView(this);
    tv.setText("User info");
    setContentView(tv);
  }

  @SuppressWarnings("deprecation")
  @Override
  protected void onResume() {
    super.onResume();
    AccountManager am=AccountManager.get(this);
    Account[] accounts = am.getAccountsByType(DarwinAuthenticator.ACCOUNT_TYPE);
    
    
    if (accounts.length>0) {
      AccountManagerCallback<Bundle> callback = new AccountManagerCallback<Bundle>() {
        
        @Override
        public void run(AccountManagerFuture<Bundle> pFuture) {
          try {
            Log.v("ACCOUNTINFO", "Got an authtoken: "+pFuture.getResult().getString(AccountManager.KEY_AUTHTOKEN));
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
  
  
  

}
