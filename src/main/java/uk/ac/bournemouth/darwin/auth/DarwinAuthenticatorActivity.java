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
import android.util.Base64;
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


/**
 * The activity that takes care of actually providing a darwin login dialog.
 */
public class DarwinAuthenticatorActivity extends AccountAuthenticatorActivity implements OnClickListener, OnEditorActionListener {

  private enum AuthResult {
    CANCELLED,
    SUCCESS,
    INVALID_CREDENTIALS,
    UNKNOWNFAILURE
  }

  @TargetApi(23)
  private static final class API23Helper {
    public static void notifyAccountAuthenticated(final AccountManager accountManager, final Account account) {
      accountManager.notifyAccountAuthenticated(account);
    }
  }

  /**
   * A task that takes care of actually authenticating the user.
   */
  private class AuthenticatorTask extends AsyncTask<Object, CharSequence, AuthResult> {

    private Account mAccount;

    @Override
    protected AuthResult doInBackground(final Object... params) {
      mAccount = (Account) params[0];
      final int i = mAccount.name.lastIndexOf('@');
      final String aUsername = i < 0 ? mAccount.name : mAccount.name.substring(0, i);
      final String password = (String) params[1];
      KeyPair keypair = null;
      if (!mConfirmCredentials) {
        publishProgress(getText(R.string.creating_keys));
        try {
          // The keypair generation is initiated on start of the activity, so it can happen while the details are entered.
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
      assert keypair!=null;
      final AuthResult authResult = registerPublicKey(mAuthBaseUrl, aUsername, password, (RSAPublicKey) (keypair.getPublic()));
      if (authResult != AuthResult.SUCCESS) {
        return authResult;
      }
      if (isCancelled()) { return AuthResult.CANCELLED; }
      return AuthResult.SUCCESS;
    }

    @SuppressWarnings("deprecation")
    @Override
    protected void onPostExecute(final AuthResult result) {
      Log.i(TAG, "Authentication result: " + result.toString());
      if (mProgressDialog != null) {
        mProgressDialog.dismiss();
      }
      switch (result) {
        case SUCCESS: {
          try {
            storeCredentials(mAccount, mKeyId, mKeypair.get(), mAuthBaseUrl);
          } catch (InterruptedException | ExecutionException e) {
            Log.e(TAG, "Retrieving keypair a second time failed. Should never happen.", e);
          }
          final Toast toast;
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
          final Toast toast = Toast.makeText(DarwinAuthenticatorActivity.this, R.string.toast_cancelled, Toast.LENGTH_SHORT);
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
    protected void onProgressUpdate(final CharSequence... values) {
      if (mProgressDialog != null) {
        mProgressDialog.setMessage(values[0]);
      }
      Log.i(TAG, "Auth progress: " + values[0]);
    }

  }

  private static void notifyAccountAuthenticated(final AccountManager accountManager, final Account account) {
    if (Build.VERSION.SDK_INT>=23) {
      API23Helper.notifyAccountAuthenticated(accountManager, account);
    }
  }

  /** {@link Account} -  The account involved in the authentication. */
  public static final String PARAM_ACCOUNT = "account";
  /** {@link String} - The user name */
  public static final String PARAM_USERNAME = "username";
  /** {@link boolean} - Indicate that this is not a login, but a confirmation. */
  public static final String PARAM_CONFIRM = "confirm";
  /** {@link boolean} - The username should not be editable. */
  public static final String PARAM_LOCK_USERNAME = "lockedUsername";
  /** {@link boolean} - The initialisation value for the password. */
  public static final String PARAM_PASSWORD = "password";
  /** {@link Object} - The id of the key. The server supports multiple ids to be registered. */
  public static final String PARAM_KEYID = "keyid";

  private static final int KEY_SIZE = 2048;
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

  private String mAuthBaseUrl;

  @Override
  protected void onCreate(final Bundle icicle) {
    super.onCreate(icicle);
    PRNGFixes.ensureApplied();

    final String username;
    String password = null;
    if (icicle != null) {
      mAccount = icicle.getParcelable(PARAM_ACCOUNT);
      if (mAccount != null) {
        username = getUsername(mAccount);
      } else {
        username = icicle.getString(PARAM_USERNAME);
      }
      mLockedUsername = icicle.getBoolean(PARAM_LOCK_USERNAME);
      mConfirmCredentials = icicle.getBoolean(PARAM_CONFIRM);
      password = icicle.getString(PARAM_PASSWORD);
      mAuthBaseUrl = icicle.getString(DarwinAuthenticator.KEY_AUTH_BASE);
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
      mAuthBaseUrl = intent.getStringExtra(DarwinAuthenticator.KEY_AUTH_BASE);
    }
    if (mAuthBaseUrl == null) { mAuthBaseUrl = DarwinAuthenticator.DEFAULT_AUTH_BASE_URL; }
    mAccountManager = AccountManager.get(this);

    if (mAccount!=null) {
      mKeyId = Long.parseLong(mAccountManager.getUserData(mAccount, PARAM_KEYID));
    }

    if (Build.VERSION.SDK_INT < 11) { // No actionbar
      requestWindowFeature(Window.FEATURE_LEFT_ICON);
    }

    mBinding = DataBindingUtil.setContentView(this, R.layout.get_password);

    if (!DarwinAuthenticator.DEFAULT_AUTH_BASE_URL.equals(mAuthBaseUrl)) {
      mBinding.authorityLabel.setText(mAuthBaseUrl);
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
    final String username;
    final int i = aAccount.name.lastIndexOf('@');
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

    final FutureTask<KeyPair> future = new FutureTask<>(new Callable<KeyPair>() {

      @SuppressLint("TrulyRandom")
      @Override
      public KeyPair call() throws Exception {
        Log.i(TAG, "Generating a pair of RSA keys");
        final KeyPairGenerator generator;
        try {
          generator = KeyPairGenerator.getInstance(DarwinAuthenticator.KEY_ALGORITHM);
        } catch (NoSuchAlgorithmException e) {
          Log.e(TAG, "The "+DarwinAuthenticator.KEY_ALGORITHM+" algorithm isn't supported on your system", e);
          return null;
        }
        generator.initialize(KEY_SIZE);
        return generator.generateKeyPair();
      }

    });

    final Thread t = new Thread(future);
    t.start();
    return future;
  }

  @Override
  protected void onSaveInstanceState(@NonNull final Bundle outState) {
    outState.putString(PARAM_USERNAME, mBinding.editUsername.getText().toString());
    outState.putString(PARAM_PASSWORD, mBinding.editPassword.getText().toString());
    outState.putBoolean(PARAM_CONFIRM, mConfirmCredentials);
    outState.putBoolean(PARAM_LOCK_USERNAME, mLockedUsername);
    outState.putString(DarwinAuthenticator.KEY_AUTH_BASE, mAuthBaseUrl);
    outState.putParcelable(PARAM_ACCOUNT, mAccount);
  }

  @Override
  protected void onStop() {
    // No need to waste effort on generating a keypair we don't use.
    synchronized (this) {
      if (mKeypair != null && (!mKeypair.isDone())) {
        mKeypair.cancel(true);
      }
    }
    super.onStop();
  }

  @SuppressWarnings("deprecation")
  @Override
  protected Dialog onCreateDialog(final int id, final Bundle args) {
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
    final Builder builder = createRetryDialogBuilder();
    return builder.setMessage(R.string.dlg_msg_error).setTitle(R.string.dlg_title_error).create();
  }

  private Dialog createInvalidAuthDialog() {
    final Builder builder = createRetryDialogBuilder();
    return builder.setMessage(R.string.dlg_msg_unauth).setTitle(R.string.dlg_title_unauth).create();
  }

  private Builder createRetryDialogBuilder() {
    final Builder builder = new AlertDialog.Builder(this);
    builder.setCancelable(true).setNegativeButton(android.R.string.cancel, new DialogInterface.OnClickListener() {
      @Override
      public void onClick(final DialogInterface dialog, final int which) {
        cancelClicked();
        dialog.dismiss();
      }
    }).setNeutralButton(R.string.retry, new DialogInterface.OnClickListener() {
      @Override
      public void onClick(final DialogInterface dialog, final int which) {
        retryClicked();
        dialog.dismiss();
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
      public void onCancel(final DialogInterface dialog) {
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
  public boolean onEditorAction(final TextView textView, final int actionId, final KeyEvent event) {
    if (textView.getId() != R.id.editPassword) { return false; }
    switch (actionId) {
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
    final String username = ((EditText) findViewById(R.id.editUsername)).getText().toString();
    final String password = ((EditText) findViewById(R.id.editPassword)).getText().toString();
    mAuthTask = new AuthenticatorTask();
    showDialog(DLG_PROGRESS);
    if (!mConfirmCredentials) {
      mKeypair = generateKeys(); // Just call again, just to be sure.
    }

    final Account account;
    final String accountName = getAccountName(username);
    if (mAccount != null && mAccount.name.equals(accountName)) {
      account = mAccount;
    } else {
      account = new Account(accountName, DarwinAuthenticator.ACCOUNT_TYPE);
    }
    mAuthTask.execute(account, password);

  }

  private String getAccountName(final String username) {
    final String accountName;
    if ((mAuthBaseUrl == null || DarwinAuthenticator.DEFAULT_AUTH_BASE_URL.equals(mAuthBaseUrl)) && username.indexOf('@') < 0) {
      accountName = username;
    } else {
      final String domain = Uri.parse(mAuthBaseUrl).getHost().toLowerCase();
      accountName = username + '@' + domain;
    }
    return accountName;
  }

  @Override
  public void onClick(final View v) {
    switch (v.getId()) {
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
    final EditText usernameEdit = ((EditText) findViewById(R.id.editUsername));
    final EditText passwordEdit = ((EditText) findViewById(R.id.editPassword));
    passwordEdit.setText("");
    usernameEdit.requestFocus();
  }

  /** Try to authenticate by registering the public key to the server. */
  private AuthResult registerPublicKey(@NonNull final String authBaseUrl, @NonNull final String username, @NonNull final String password, @NonNull final RSAPublicKey publicKey) {
    final String encodedPublicKey = DarwinAuthenticator.encodePublicKey(publicKey);
    Log.d(TAG, "registering encoded public key at id ("+mKeyId+"):"+encodedPublicKey);
    Log.d(TAG, "public exp:"+Base64.encodeToString(publicKey.getPublicExponent().toByteArray(), 0));
    Log.d(TAG, "public mod:"+Base64.encodeToString(publicKey.getModulus().toByteArray(), 0));
    final HttpURLConnection conn;
    try {
      conn = (HttpURLConnection) DarwinAuthenticator.getAuthenticateUrl(authBaseUrl).toURL().openConnection();
      try {
        conn.setRequestMethod("POST");
        conn.setDoOutput(true);
        conn.setRequestProperty("Content-Type", "application/x-www-form-urlencoded;charset=utf8");
        {
          final BufferedWriter out = new BufferedWriter(new OutputStreamWriter(conn.getOutputStream(), Util.UTF8));
          try {
            out.write("username=");
            out.write(URLEncoder.encode(username, Util.UTF8.name()));
            out.write("&password=");
            out.write(URLEncoder.encode(password, Util.UTF8.name()));
            out.write("&app=");
            out.write(URLEncoder.encode(getAppName(), Util.UTF8.name()));
            if (encodedPublicKey != null) {
              out.write("&pubkey=");
              out.write(encodedPublicKey);
            }
            if (mKeyId >= 0) {
              out.write("&id=" + mKeyId);
            }
          } finally {
            out.close();
          }
        }

        final int response = conn.getResponseCode();
        Log.i(TAG, "Authentication response code: " + response);
        if (response == HttpURLConnection.HTTP_FORBIDDEN) {
          return AuthResult.INVALID_CREDENTIALS;
        } else if (response >= 200 && response < 400) {
          final BufferedReader in = new BufferedReader(new InputStreamReader(conn.getInputStream(), Util.UTF8));
          try {
            String line = in.readLine();
            while (line != null) {
              final int p = line.indexOf(':');
              if (p >= 0 && "key".equals(line.substring(0, p).trim())) {
                mKeyId = Long.parseLong(line.substring(p + 1).trim());
              }
              line = in.readLine();
            }
          } finally {
            in.close();
          }
          if (mKeyId>=0) return AuthResult.SUCCESS;
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

  private static String getAppName() {
    if(Build.MODEL.contains(Build.MANUFACTURER)) { return "DarwinAuthenticator on "+Build.MODEL; }
    return "DarwinAuthenticator on " + Build.MANUFACTURER + ' ' + Build.MODEL;
  }

  private static void logStream(final InputStream errorStream) throws IOException {
    final BufferedReader einn = new BufferedReader(new InputStreamReader(errorStream));
    try {
      String line = einn.readLine();
      Log.d(TAG, "Authentication error response: ");
      while (line != null) {
        Log.d(TAG, "> " + line);
        line = einn.readLine();
      }
    } finally {
      einn.close();
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
  private void storeCredentials(@NonNull final Account account, final long keyId, @NonNull final KeyPair keyPair, @NonNull final String authbase) {
    final String keyspec = DarwinAuthenticator.encodePrivateKey((RSAPrivateKey) keyPair.getPrivate());

    boolean updateUser=mLockedUsername;
    if (!updateUser) {
      final Bundle bundle = new Bundle(3);
      bundle.putString(DarwinAuthenticator.KEY_PRIVATEKEY, keyspec);
      bundle.putString(DarwinAuthenticator.KEY_KEYID, Long.toString(keyId));
      bundle.putString(DarwinAuthenticator.KEY_AUTH_BASE, authbase);
      updateUser = !mAccountManager.addAccountExplicitly(account, null, bundle);
    }

    if(updateUser){
      mAccountManager.setUserData(account, DarwinAuthenticator.KEY_PRIVATEKEY, keyspec);
      mAccountManager.setUserData(account, DarwinAuthenticator.KEY_KEYID, Long.toString(keyId));
      mAccountManager.setUserData(account, DarwinAuthenticator.KEY_AUTH_BASE, authbase);
    }
  }

}
