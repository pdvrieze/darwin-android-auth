package uk.ac.bournemouth.darwin.auth;

import android.accounts.AccountAuthenticatorActivity;
import android.content.Intent;
import android.os.Build;
import android.os.Bundle;
import android.view.Window;


public class DarwinAuthenticatorActivity extends AccountAuthenticatorActivity {

  static final String PARAM_USERNAME = "username";
  static final String PARAM_CONFIRM = "confirm";
  private String aUsername;
  private boolean aRequestNewAccount;
  private boolean aConfirmCredentials;

  @Override
  protected void onCreate(Bundle pIcicle) {
    super.onCreate(pIcicle);
    
    final Intent intent = getIntent();
    
    aUsername = intent.getStringExtra(PARAM_USERNAME);
    aRequestNewAccount = aUsername==null;
    aConfirmCredentials = intent.getBooleanExtra(PARAM_CONFIRM, false);
    
    if (Build.VERSION.SDK_INT<11) { // No actionbar
      requestWindowFeature(Window.FEATURE_LEFT_ICON);
    }
    setContentView(R.layout.get_password);
    
    
    
  }

}
