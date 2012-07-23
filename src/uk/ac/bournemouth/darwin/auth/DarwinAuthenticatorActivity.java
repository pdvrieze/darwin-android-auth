package uk.ac.bournemouth.darwin.auth;

import android.accounts.AccountAuthenticatorActivity;
import android.os.Build;
import android.os.Bundle;
import android.view.Window;


public class DarwinAuthenticatorActivity extends AccountAuthenticatorActivity {

  @Override
  protected void onCreate(Bundle pIcicle) {
    super.onCreate(pIcicle);
    
    if (Build.VERSION.SDK_INT<11) { // No actionbar
      requestWindowFeature(Window.FEATURE_LEFT_ICON);
    }
    setContentView(R.layout.get_password);
    
  }

}
