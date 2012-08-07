package uk.ac.bournemouth.darwin.auth;

import java.io.*;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URLEncoder;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Future;
import java.util.concurrent.FutureTask;

import javax.net.ssl.HttpsURLConnection;

import android.accounts.Account;
import android.accounts.AccountAuthenticatorActivity;
import android.accounts.AccountManager;
import android.app.AlertDialog;
import android.app.AlertDialog.Builder;
import android.app.Dialog;
import android.app.ProgressDialog;
import android.content.DialogInterface;
import android.content.Intent;
import android.os.AsyncTask;
import android.os.Build;
import android.os.Bundle;
import android.util.Log;
import android.view.KeyEvent;
import android.view.View;
import android.view.View.OnClickListener;
import android.view.Window;
import android.view.inputmethod.EditorInfo;
import android.widget.*;
import android.widget.TextView.OnEditorActionListener;


public class DarwinAuthenticatorActivity extends AccountAuthenticatorActivity implements OnClickListener, OnEditorActionListener {

  private static final int KEY_SIZE = 128;

  private static enum AuthResult {
    CANCELLED,
    SUCCESS,
    INVALID_CREDENTIALS,
    UNKNOWNFAILURE
  }
  
  
  public class AuthenticatorTask extends AsyncTask<String, CharSequence, AuthResult> {

    private String aUsername;

    @Override
    protected AuthResult doInBackground(String... pParams) {
      aUsername = pParams[0];
      String password = pParams[1];
      KeyPair keypair=null;
      if (!aConfirmCredentials) {
        publishProgress(getText(R.string.creating_keys));
        try {
          keypair = aKeypair.get();
        } catch (InterruptedException e) {
          if (isCancelled()) { 
            return AuthResult.CANCELLED;
          } else {
            return AuthResult.UNKNOWNFAILURE;
          }
        } catch (ExecutionException e) {
          Log.w(TAG, "Getting keypair failed", e.getCause());
          return AuthResult.UNKNOWNFAILURE;
        }
        if (isCancelled()) { return AuthResult.CANCELLED; }
      }
      
      publishProgress(getText(R.string.authenticating));
      AuthResult authResult = registerPublicKey(aUsername, password, (RSAPublicKey) (keypair==null?null:keypair.getPublic()));
      if (authResult!=AuthResult.SUCCESS) {
        return authResult;
      }
      if (isCancelled()) { return AuthResult.CANCELLED; }
      storeCredentials(aUsername, aKeyId, keypair);
      return AuthResult.SUCCESS;
    }

    @Override
    protected void onProgressUpdate(CharSequence... pValues) {
      if (aProgressDialog!=null) {
        aProgressDialog.setMessage(pValues[0]);
      }
      Log.i(TAG, "Auth progress: "+pValues[0]);
    }

    @SuppressWarnings("deprecation")
    @Override
    protected void onPostExecute(AuthResult pResult) {
      Log.i(TAG, "Authentication result: "+pResult.toString());
      if (aProgressDialog!=null) {
        aProgressDialog.dismiss();
      }
      switch (pResult) {
        case SUCCESS: {
          Toast toast;
          if (aConfirmCredentials) {
            toast=Toast.makeText(DarwinAuthenticatorActivity.this, R.string.toast_update_success, Toast.LENGTH_SHORT);
          } else {
            toast=Toast.makeText(DarwinAuthenticatorActivity.this, R.string.toast_create_success, Toast.LENGTH_SHORT);
          }
          final Intent intent = new Intent();
          intent.putExtra(AccountManager.KEY_ACCOUNT_NAME, aUsername);
          intent.putExtra(AccountManager.KEY_ACCOUNT_TYPE, DarwinAuthenticator.ACCOUNT_TYPE);
          setAccountAuthenticatorResult(intent.getExtras());
          setResult(RESULT_OK, intent);
          toast.show();
          finish();
          break;
        }
        case CANCELLED: {
          Toast toast=Toast.makeText(DarwinAuthenticatorActivity.this, R.string.toast_cancelled, Toast.LENGTH_SHORT);
          toast.show();
          finish();
          break;
        }
        case UNKNOWNFAILURE: {
          showDialog(DLG_ERROR);
          break;
        }
        case INVALID_CREDENTIALS: {
          showDialog(DLG_INVALIDAUTH);
          break;
        }
      }
    }

  }

  static final String PARAM_USERNAME = "username";
  static final String PARAM_CONFIRM = "confirm";
  static final String PARAM_LOCK_USERNAME = "lockedUsername";
  static final String PARAM_PASSWORD = "password";
  static final String PARAM_KEYID = "keyid";
  private static final String TAG = DarwinAuthenticatorActivity.class.getName();
  private static final int DLG_PROGRESS = 0;
  private static final int DLG_ERROR = 1;
  private static final int DLG_INVALIDAUTH = 2;
  private long aKeyId=-1l;
//  private String aUsername;
  private boolean aConfirmCredentials;
  private AuthenticatorTask aAuthTask;
  private ProgressDialog aProgressDialog;
  private AccountManager aAccountManager;
  private Future<KeyPair> aKeypair;
  private EditText aEditUsername;
  private EditText aEditPassword;
  private boolean aLockedUsername;

  @Override
  protected void onCreate(Bundle pIcicle) {
    super.onCreate(pIcicle);
    
    String username;
    String password=null;
    if (pIcicle!=null) {
      username = pIcicle.getString(PARAM_USERNAME);
      aLockedUsername = pIcicle.getBoolean(PARAM_LOCK_USERNAME);
      aConfirmCredentials = pIcicle.getBoolean(PARAM_CONFIRM);
      password = pIcicle.getString(PARAM_PASSWORD);
    } else {
      final Intent intent = getIntent();
      
      username= intent.getStringExtra(PARAM_USERNAME);
      aLockedUsername = username!=null && username.length()>0;
      aConfirmCredentials = intent.getBooleanExtra(PARAM_CONFIRM, false);
    }
    aAccountManager = AccountManager.get(this);
    
    if (Build.VERSION.SDK_INT<11) { // No actionbar
      requestWindowFeature(Window.FEATURE_LEFT_ICON);
    }
    
    setContentView(R.layout.get_password);
    
    aEditUsername = (EditText) findViewById(R.id.editUsername);
    if (aLockedUsername) {
      aEditUsername.setText(username);
      aEditUsername.setEnabled(false); // Fixed username, so disable editing
    }
    
    aEditPassword = (EditText) findViewById(R.id.editPassword);
    aEditPassword.setOnEditorActionListener(this);
    if (password!=null) { aEditPassword.setText(password); }
    
    Button cancelButton = (Button) findViewById(R.id.cancelbutton);
    Button okButton = (Button) findViewById(R.id.okbutton);
    cancelButton.setOnClickListener(this);
    okButton.setOnClickListener(this);
    
    if (!aConfirmCredentials) {
      aKeypair = generateKeys();
    }
  }

  @Override
  protected void onSaveInstanceState(Bundle pOutState) {
    pOutState.putString(PARAM_USERNAME, aEditUsername.getText().toString());
    pOutState.putString(PARAM_PASSWORD, aEditPassword.getText().toString());
    pOutState.putBoolean(PARAM_CONFIRM, aConfirmCredentials);
    pOutState.putBoolean(PARAM_LOCK_USERNAME, aLockedUsername);
  }

  @Override
  protected void onStop() {
    // No need to waste effort on generating a keypair we don't use.
    synchronized(this) {
      if (aKeypair!=null && (!aKeypair.isDone())) {
        if (aKeypair.cancel(true));
      }
    }
    super.onStop();
  }

  @Override
  protected Dialog onCreateDialog(int id, Bundle args) {
    switch (id) {
      case DLG_PROGRESS: {
        return createProcessDialog();
      }
      case DLG_ERROR: {
        return createErrorDialog();
      }
      case DLG_INVALIDAUTH: {
        return createInvalidAuthDialog();
      }
      default:
        return null;
    }
  }

  private Dialog createErrorDialog() {
    Builder builder = createRetryDialogBuilder();
    return builder.setMessage(R.string.dlg_msg_error)
                  .setTitle(R.string.dlg_title_error).create();
  }

  private Dialog createInvalidAuthDialog() {
    Builder builder = createRetryDialogBuilder();
    return builder.setMessage(R.string.dlg_msg_unauth)
                  .setTitle(R.string.dlg_title_unauth).create();
  }

  private Builder createRetryDialogBuilder() {
    Builder builder = new AlertDialog.Builder(this);
    builder.setCancelable(true)
           .setNegativeButton(android.R.string.cancel, new DialogInterface.OnClickListener() {
              @Override
              public void onClick(DialogInterface pDialog, int pWhich) {
                cancelClicked();
                pDialog.dismiss();
              }
            })
            .setNeutralButton(R.string.retry, new DialogInterface.OnClickListener() {
              @Override
              public void onClick(DialogInterface pDialog, int pWhich) {
                retryClicked();
                pDialog.dismiss();
              }
            });
    return builder;
  }

  private Dialog createProcessDialog() {
    final ProgressDialog dialog = new ProgressDialog(this);
    dialog.setMessage(getText(R.string.authenticating));
    dialog.setIndeterminate(true);
    dialog.setCancelable(true);
    dialog.setCanceledOnTouchOutside(false);
    dialog.setOnCancelListener(new DialogInterface.OnCancelListener() {
        public void onCancel(DialogInterface dialog) {
            Log.i(TAG, "user cancelling authentication");
            if (aAuthTask != null) {
                aAuthTask.cancel(true);
            }
        }
    });
    // We save off the progress dialog in a field so that we can dismiss
    // it later. We can't just call dismissDialog(0) because the system
    // can lose track of our dialog if there's an orientation change.
    aProgressDialog = dialog;
    return dialog;
  }
  
  @Override
  public boolean onEditorAction(TextView pV, int pActionId, KeyEvent pEvent) {
    if (pV.getId()!=R.id.editPassword) { return false; }
    switch (pActionId) {
      case EditorInfo.IME_NULL:
      case EditorInfo.IME_ACTION_DONE:
      case EditorInfo.IME_ACTION_GO:
        startAuthentication();
        return true;
    }
    return false;
  }

  @Override
  public void onClick(View pV) {
    switch (pV.getId()) {
      case R.id.cancelbutton:
        cancelClicked();
        break;
      case R.id.okbutton:
        startAuthentication();
        break;
    }
  }

  private void cancelClicked() {
    finish();
  }

  private void retryClicked() {
    EditText usernameEdit = ((EditText) findViewById(R.id.editUsername));
    EditText passwordEdit = ((EditText) findViewById(R.id.editPassword));
    passwordEdit.setText("");
    usernameEdit.requestFocus();
  }

  /** 
   * Handle the creation of an account.
   */
  @SuppressWarnings("deprecation")
  private void startAuthentication() {
    String username = ((EditText) findViewById(R.id.editUsername)).getText().toString();
    String password = ((EditText) findViewById(R.id.editPassword)).getText().toString();
    aAuthTask = new AuthenticatorTask();
    showDialog(DLG_PROGRESS);
    if (!aConfirmCredentials) {
      aKeypair=generateKeys(); // Just call again, just to be sure.
    }
    aAuthTask.execute(username, password);
    
  }
  
  private Future<KeyPair> generateKeys() {
    synchronized (this) {
      if (aKeypair!=null) {
        try {
          if (aKeypair.isCancelled()||(aKeypair.isDone()&& aKeypair.get()==null)) {
            aKeypair=null; // Remove the previous pair
          } else {
            return aKeypair; // We're still in progress, just bail out.
          }
        } catch (InterruptedException e) {
          aKeypair=null;
        } catch (ExecutionException e) {
          aKeypair=null;
          Log.w(TAG, "Error generating keys", e);
        }
      }
    }

    FutureTask<KeyPair> future = new FutureTask<KeyPair>(new Callable<KeyPair>() {

      @Override
      public KeyPair call() throws Exception {
        Log.i(TAG, "Generating a pair of RSA keys");
        KeyPairGenerator generator;
        try {
          generator = KeyPairGenerator.getInstance(DarwinAuthenticator.KEY_ALGORITHM);
        } catch (NoSuchAlgorithmException e) {
          Log.e(TAG, "The RSA algorithm isn't supported on your system", e);
          return null;
        }
        generator.initialize(KEY_SIZE);
        return generator.generateKeyPair();
      }
      
    });
    
    Thread t = new Thread(future);
    t.start();
    return future;
  }

  /** Try to authenticate by registering the public key to the server. */
  AuthResult registerPublicKey(String pUsername, String pPassword, RSAPublicKey pPublicKey) {
    String publicKey = pPublicKey==null ? null : DarwinAuthenticator.encodePublicKey(pPublicKey);
    HttpsURLConnection conn;
    try {
      conn = (HttpsURLConnection) DarwinAuthenticator.AUTHENTICATE_URL.toURL().openConnection();
      try {
        conn.setRequestMethod("POST");
        conn.setDoOutput(true);
        conn.setRequestProperty("Content-Type", "application/x-www-form-urlencoded;charset=utf8");
        BufferedWriter out = new BufferedWriter(new OutputStreamWriter(conn.getOutputStream(), Util.UTF8));
        out.write("username=");
        out.write(URLEncoder.encode(pUsername, Util.UTF8.name()));
        out.write("&password=");
        out.write(URLEncoder.encode(pPassword, Util.UTF8.name()));
        if (publicKey!=null) {
          out.write("&pubkey=");
          out.write(publicKey);
        }
        if (aKeyId>=0) {
          out.write("&id="+aKeyId);
        }
        out.close();
        
        int response = conn.getResponseCode();
        Log.i(TAG, "Authentication response code: "+response);
        if (response == HttpURLConnection.HTTP_FORBIDDEN) {
          return AuthResult.INVALID_CREDENTIALS;
        } else if (response>=200 && response <400) {
          BufferedReader in=new BufferedReader(new InputStreamReader(conn.getInputStream(), Util.UTF8));
          String line = in.readLine();
          while (line!=null) {
            int p = line.indexOf(':');
            if (p>=0 && "key".equals(line.substring(0, p).trim())) {
              aKeyId = Long.parseLong(line.substring(p+1).trim());
            }
            line = in.readLine();
          }
          return AuthResult.SUCCESS;
        } else {
          logStream(conn.getErrorStream());
        }
      } finally {
        conn.disconnect();
      }
      return AuthResult.UNKNOWNFAILURE;
    } catch (MalformedURLException e) {
      Log.e(TAG, "Should never happen", e);
      return AuthResult.UNKNOWNFAILURE;
    } catch (IOException e) {
      Log.d(TAG, "Failure registering keys", e);
      return AuthResult.UNKNOWNFAILURE;
    }
  }

  /**
   * Record they private key and username to the account manager.
   * @param pUsername
   * @param pKeyId 
   * @param pKeypair
   */
  private void storeCredentials(String pUsername, long pKeyId, KeyPair pKeypair) {
    if (pKeypair==null) { return; }
    Account account = new Account(pUsername, DarwinAuthenticator.ACCOUNT_TYPE);
    String keyspec = DarwinAuthenticator.encodePrivateKey((RSAPrivateKey) pKeypair.getPrivate());
    if (! aLockedUsername) {
      Bundle bundle = new Bundle();
      bundle.putString(DarwinAuthenticator.KEY_PRIVATEKEY, keyspec);
      bundle.putString(DarwinAuthenticator.KEY_KEYID, Long.toString(pKeyId));
      aAccountManager.addAccountExplicitly(account, null, bundle);
    } else {
      aAccountManager.setUserData(account, DarwinAuthenticator.KEY_PRIVATEKEY, keyspec);
    }
  }

  private static void logStream(final InputStream errorStream) throws IOException {
    BufferedReader einn = new BufferedReader(new InputStreamReader(errorStream));
    String line = einn.readLine();
    Log.d(TAG, "Authentication error response: ");
    while (line!=null) {
      Log.d(TAG, "> "+line);
      line = einn.readLine();
    }
  }

}
