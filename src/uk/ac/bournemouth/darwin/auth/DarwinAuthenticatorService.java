package uk.ac.bournemouth.darwin.auth;

import android.app.Service;
import android.content.Intent;
import android.os.IBinder;


public class DarwinAuthenticatorService extends Service {

  private DarwinAuthenticator aAuthenticator;

  @Override
  public void onCreate() {
    super.onCreate();
    aAuthenticator = new DarwinAuthenticator(this);
  }

  @Override
  public IBinder onBind(Intent pArg0) {
    return aAuthenticator.getIBinder();
  }

}
