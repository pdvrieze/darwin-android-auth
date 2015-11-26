package uk.ac.bournemouth.darwin.auth;

import android.accounts.Account;
import android.accounts.AccountAuthenticatorActivity;
import android.accounts.AccountManager;
import android.annotation.SuppressLint;
import android.annotation.TargetApi;
import android.app.AlertDialog;
import android.app.AlertDialog.Builder;
import android.app.Dialog;
import android.app.ProgressDialog;
import android.content.DialogInterface;
import android.content.Intent;
import android.databinding.DataBindingUtil;
import android.net.Uri;
import android.os.AsyncTask;
import android.os.Build;
import android.os.Bundle;
import android.support.annotation.NonNull;
import android.util.Log;
import android.view.KeyEvent;
import android.view.View;
import android.view.View.OnClickListener;
import android.view.Window;
import android.view.inputmethod.EditorInfo;
import android.widget.EditText;
import android.widget.TextView;
import android.widget.TextView.OnEditorActionListener;
import android.widget.Toast;
import uk.ac.bournemouth.darwin.auth.databinding.DarwinAuthenticatorActivityBinding;

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


public class DarwinAuthenticatorActivity extends AccountAuthenticatorActivity implements OnClickListener, OnEditorActionListener {

  private enum AuthResult {
    CANCELLED,
    SUCCESS,
    INVALID_CREDENTIALS,
    UNKNOWNFAILURE
  }

  @TargetApi(23)
  private static class API23Helper {
    public static void notifyAccountAuthenticated(final AccountManager accountManager, final Account account) {
      accountManager.notifyAccountAuthenticated(account);
    }
  }

  public class AuthenticatorTask extends AsyncTask<Object, CharSequence, AuthResult> {

    private Account mAccount;

    @Override
    protected AuthResult doInBackground(Object... pParams) {
      mAccount = (Account) pParams[0];
      int i = mAccount.name.lastIndexOf('@');
      String aUsername = i < 0 ? mAccount.name : mAccount.name.substring(0, '@');
      String password = (String) pParams[1];
      KeyPair keypair = null;
      if (!mConfirmCredentials) {
        publishProgress(getText(R.string.creating_keys));
        try {
          keypair = mKeypair.get();
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
      AuthResult authResult = registerPublicKey(aAuthBaseUrl, aUsername, password, (RSAPublicKey) (keypair == null ? null : keypair
              .getPublic()));
      if (authResult != AuthResult.SUCCESS) {
        return authResult;
      }
      if (isCancelled()) { return AuthResult.CANCELLED; }
      return AuthResult.SUCCESS;
    }

    @SuppressWarnings("deprecation")
    @Override
    protected void onPostExecute(AuthResult pResult) {
      Log.i(TAG, "Authentication result: " + pResult.toString());
      if (mProgressDialog != null) {
        mProgressDialog.dismiss();
      }
      switch (pResult) {
        case SUCCESS: {
          try {
            storeCredentials(mAccount, mKeyId, mKeypair.get(), aAuthBaseUrl);
          } catch (InterruptedException | ExecutionException e) {
            Log.e(TAG, "Retrieving keypair a second time failed. Should never happen.", e);
          }
          Toast toast;
          if (mConfirmCredentials) {
            toast = Toast.makeText(DarwinAuthenticatorActivity.this, R.string.toast_update_success, Toast.LENGTH_SHORT);
          } else {
            toast = Toast.makeText(DarwinAuthenticatorActivity.this, R.string.toast_create_success, Toast.LENGTH_SHORT);
          }
          notifyAccountAuthenticated(mAccountManager, mAccount);

          final Intent intent = new Intent();
          intent.putExtra(AccountManager.KEY_ACCOUNT_NAME, mAccount.name);
          intent.putExtra(AccountManager.KEY_ACCOUNT_TYPE, DarwinAuthenticator.ACCOUNT_TYPE);
          setAccountAuthenticatorResult(intent.getExtras());
          setResult(RESULT_OK, intent);
          toast.show();
          finish();
          break;
        }
        case CANCELLED: {
          Toast toast = Toast.makeText(DarwinAuthenticatorActivity.this, R.string.toast_cancelled, Toast.LENGTH_SHORT);
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

    @Override
    protected void onProgressUpdate(CharSequence... pValues) {
      if (mProgressDialog != null) {
        mProgressDialog.setMessage(pValues[0]);
      }
      Log.i(TAG, "Auth progress: " + pValues[0]);
    }

  }

  private static void notifyAccountAuthenticated(final AccountManager accountManager, final Account account) {
    if (Build.VERSION.SDK_INT>=23) {
      API23Helper.notifyAccountAuthenticated(accountManager, account);
    }
  }

  public static final String PARAM_ACCOUNT = "account";
  public static final String PARAM_USERNAME = "username";
  public static final String PARAM_CONFIRM = "confirm";
  public static final String PARAM_LOCK_USERNAME = "lockedUsername";
  public static final String PARAM_PASSWORD = "password";
  public static final String PARAM_KEYID = "keyid";

  private static final int KEY_SIZE = 1024;
  private static final String TAG = DarwinAuthenticatorActivity.class.getName();
  private static final int DLG_PROGRESS = 0;
  private static final int DLG_ERROR = 1;
  private static final int DLG_INVALIDAUTH = 2;

  private long mKeyId = -1L;
  private boolean mConfirmCredentials;
  private AuthenticatorTask mAuthTask;
  private ProgressDialog mProgressDialog;
  private AccountManager mAccountManager;
  private Future<KeyPair> mKeypair;
  private DarwinAuthenticatorActivityBinding mBinding;
  private boolean mLockedUsername;
  private Account mAccount;

  private String aAuthBaseUrl;

  @Override
  protected void onCreate(Bundle pIcicle) {
    super.onCreate(pIcicle);
    PRNGFixes.ensureApplied();

    Account account;
    String username;
    String password = null;
    if (pIcicle != null) {
      mAccount = pIcicle.getParcelable(PARAM_ACCOUNT);
      if (mAccount != null) {
        username = getUsername(mAccount);
      } else {
        username = pIcicle.getString(PARAM_USERNAME);
      }
      mLockedUsername = pIcicle.getBoolean(PARAM_LOCK_USERNAME);
      mConfirmCredentials = pIcicle.getBoolean(PARAM_CONFIRM);
      password = pIcicle.getString(PARAM_PASSWORD);
      aAuthBaseUrl = pIcicle.getString(DarwinAuthenticator.KEY_AUTH_BASE);
    } else {
      final Intent intent = getIntent();

      mAccount = intent.getParcelableExtra(PARAM_ACCOUNT);
      if (mAccount != null) {
        username = getUsername(mAccount);
      } else {
        username = intent.getStringExtra(PARAM_USERNAME);
      }

      mLockedUsername = username != null && username.length() > 0;
      mConfirmCredentials = intent.getBooleanExtra(PARAM_CONFIRM, false);
      aAuthBaseUrl = intent.getStringExtra(DarwinAuthenticator.KEY_AUTH_BASE);
    }
    if (aAuthBaseUrl == null) { aAuthBaseUrl = DarwinAuthenticator.DEFAULT_AUTH_BASE_URL; }
    mAccountManager = AccountManager.get(this);

    if (Build.VERSION.SDK_INT < 11) { // No actionbar
      requestWindowFeature(Window.FEATURE_LEFT_ICON);
    }

    mBinding = DataBindingUtil.setContentView(this, R.layout.get_password);

    if (!DarwinAuthenticator.DEFAULT_AUTH_BASE_URL.equals(aAuthBaseUrl)) {
      mBinding.authorityLabel.setText(aAuthBaseUrl);
    }

    mBinding.editUsername.setText(username);
    if (mLockedUsername) {
      mBinding.editUsername.setEnabled(false); // Fixed username, so disable editing
    }

    mBinding.editPassword.setOnEditorActionListener(this);
    if (password != null) { mBinding.editPassword.setText(password); }


    mBinding.cancelbutton.setOnClickListener(this);
    mBinding.okbutton.setOnClickListener(this);

    if (!mConfirmCredentials) {
      mKeypair = generateKeys();
    }
  }

  private static String getUsername(final Account aAccount) {
    String username;
    int i = aAccount.name.lastIndexOf('@');
    if (i>=0) {
      username = aAccount.name.substring(0, i);
    } else {
      username = aAccount.name;
    }
    return username;
  }

  private Future<KeyPair> generateKeys() {
    synchronized (this) {
      if (mKeypair != null) {
        try {
          if (mKeypair.isCancelled() || (mKeypair.isDone() && mKeypair.get() == null)) {
            mKeypair = null; // Remove the previous pair
          } else {
            return mKeypair; // We're still in progress, just bail out.
          }
        } catch (InterruptedException e) {
          mKeypair = null;
        } catch (ExecutionException e) {
          mKeypair = null;
          Log.w(TAG, "Error generating keys", e);
        }
      }
    }

    FutureTask<KeyPair> future = new FutureTask<>(new Callable<KeyPair>() {

      @SuppressLint("TrulyRandom")
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

  @Override
  protected void onSaveInstanceState(Bundle pOutState) {
    pOutState.putString(PARAM_USERNAME, mBinding.editUsername.getText().toString());
    pOutState.putString(PARAM_PASSWORD, mBinding.editPassword.getText().toString());
    pOutState.putBoolean(PARAM_CONFIRM, mConfirmCredentials);
    pOutState.putBoolean(PARAM_LOCK_USERNAME, mLockedUsername);
    pOutState.putString(DarwinAuthenticator.KEY_AUTH_BASE, aAuthBaseUrl);
    pOutState.putParcelable(PARAM_ACCOUNT, mAccount);
  }

  @Override
  protected void onStop() {
    // No need to waste effort on generating a keypair we don't use.
    synchronized (this) {
      if (mKeypair != null && (!mKeypair.isDone())) {
        if (mKeypair.cancel(true)) { ; }
      }
    }
    super.onStop();
  }

  @SuppressWarnings("deprecation")
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
    return builder.setMessage(R.string.dlg_msg_error).setTitle(R.string.dlg_title_error).create();
  }

  private Dialog createInvalidAuthDialog() {
    Builder builder = createRetryDialogBuilder();
    return builder.setMessage(R.string.dlg_msg_unauth).setTitle(R.string.dlg_title_unauth).create();
  }

  private Builder createRetryDialogBuilder() {
    Builder builder = new AlertDialog.Builder(this);
    builder.setCancelable(true).setNegativeButton(android.R.string.cancel, new DialogInterface.OnClickListener() {
      @Override
      public void onClick(DialogInterface pDialog, int pWhich) {
        cancelClicked();
        pDialog.dismiss();
      }
    }).setNeutralButton(R.string.retry, new DialogInterface.OnClickListener() {
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
      @Override
      public void onCancel(DialogInterface pDialog) {
        Log.i(TAG, "user cancelling authentication");
        if (mAuthTask != null) {
          mAuthTask.cancel(true);
        }
      }
    });
    // We save off the progress dialog in a field so that we can dismiss
    // it later. We can't just call dismissDialog(0) because the system
    // can lose track of our dialog if there's an orientation change.
    mProgressDialog = dialog;
    return dialog;
  }

  @Override
  public boolean onEditorAction(TextView pV, int pActionId, KeyEvent pEvent) {
    if (pV.getId() != R.id.editPassword) { return false; }
    switch (pActionId) {
      case EditorInfo.IME_NULL:
      case EditorInfo.IME_ACTION_DONE:
      case EditorInfo.IME_ACTION_GO:
        startAuthentication();
        return true;
    }
    return false;
  }

  /**
   * Handle the creation of an account.
   */
  @SuppressWarnings("deprecation")
  private void startAuthentication() {
    String username = ((EditText) findViewById(R.id.editUsername)).getText().toString();
    String password = ((EditText) findViewById(R.id.editPassword)).getText().toString();
    mAuthTask = new AuthenticatorTask();
    showDialog(DLG_PROGRESS);
    if (!mConfirmCredentials) {
      mKeypair = generateKeys(); // Just call again, just to be sure.
    }

    Account account;
    String accountName = getAccountName(username);
    if (mAccount != null && mAccount.name.equals(accountName)) {
      account = mAccount;
    } else {
      account = new Account(accountName, DarwinAuthenticator.ACCOUNT_TYPE);
    }
    mAuthTask.execute(account, password);

  }

  private String getAccountName(final String username) {
    final String accountName;
    if ((aAuthBaseUrl == null || DarwinAuthenticator.DEFAULT_AUTH_BASE_URL.equals(aAuthBaseUrl)) && username.indexOf('@') < 0) {
      accountName = username;
    } else {
      String domain = Uri.parse(aAuthBaseUrl).getHost().toLowerCase();
      accountName = username + '@' + domain;
    }
    return accountName;
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

  /** Try to authenticate by registering the public key to the server. */
  AuthResult registerPublicKey(String authBaseUrl, String pUsername, String pPassword, RSAPublicKey pPublicKey) {
    String publicKey = pPublicKey == null ? null : DarwinAuthenticator.encodePublicKey(pPublicKey);
    HttpURLConnection conn;
    try {
      conn = (HttpURLConnection) DarwinAuthenticator.getAuthenticateUrl(authBaseUrl).toURL().openConnection();
      try {
        conn.setRequestMethod("POST");
        conn.setDoOutput(true);
        conn.setRequestProperty("Content-Type", "application/x-www-form-urlencoded;charset=utf8");
        BufferedWriter out = new BufferedWriter(new OutputStreamWriter(conn.getOutputStream(), Util.UTF8));
        out.write("username=");
        out.write(URLEncoder.encode(pUsername, Util.UTF8.name()));
        out.write("&password=");
        out.write(URLEncoder.encode(pPassword, Util.UTF8.name()));
        if (publicKey != null) {
          out.write("&pubkey=");
          out.write(publicKey);
        }
        if (mKeyId >= 0) {
          out.write("&id=" + mKeyId);
        }
        out.close();

        int response = conn.getResponseCode();
        Log.i(TAG, "Authentication response code: " + response);
        if (response == HttpURLConnection.HTTP_FORBIDDEN) {
          return AuthResult.INVALID_CREDENTIALS;
        } else if (response >= 200 && response < 400) {
          BufferedReader in = new BufferedReader(new InputStreamReader(conn.getInputStream(), Util.UTF8));
          String line = in.readLine();
          while (line != null) {
            int p = line.indexOf(':');
            if (p >= 0 && "key".equals(line.substring(0, p).trim())) {
              mKeyId = Long.parseLong(line.substring(p + 1).trim());
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

  private static void logStream(final InputStream errorStream) throws IOException {
    BufferedReader einn = new BufferedReader(new InputStreamReader(errorStream));
    String line = einn.readLine();
    Log.d(TAG, "Authentication error response: ");
    while (line != null) {
      Log.d(TAG, "> " + line);
      line = einn.readLine();
    }
  }

  /**
   * Record they private key and username to the account manager.
   *
   * @param account  The account for the account manager
   * @param keyId    The id of the key involved.
   * @param keyPair  The actual keypair to record for this user.
   * @param authbase The url that is the basis for this authentication. One authenticator can support multiple bases with
   */
  private void storeCredentials(@NonNull Account account, long keyId, @NonNull KeyPair keyPair, @NonNull String authbase) {
    if (keyPair == null) { return; }
    String keyspec = DarwinAuthenticator.encodePrivateKey((RSAPrivateKey) keyPair.getPrivate());
    if (!mLockedUsername) {
      Bundle bundle = new Bundle(3);
      bundle.putString(DarwinAuthenticator.KEY_PRIVATEKEY, keyspec);
      bundle.putString(DarwinAuthenticator.KEY_KEYID, Long.toString(keyId));
      bundle.putString(DarwinAuthenticator.KEY_AUTH_BASE, authbase);
      mAccountManager.addAccountExplicitly(account, null, bundle);
    } else {
      mAccountManager.setUserData(account, DarwinAuthenticator.KEY_PRIVATEKEY, keyspec);
      mAccountManager.setUserData(account, DarwinAuthenticator.KEY_KEYID, Long.toString(keyId));
    }
  }

}
