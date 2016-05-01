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
import android.content.Context;
import android.content.Intent;
import android.os.Bundle;
import android.os.Process;
import android.text.TextUtils.SimpleStringSplitter;
import android.util.Base64;
import android.util.Log;
import android.util.Pair;

import javax.crypto.Cipher;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URI;
import java.nio.ByteBuffer;
import java.nio.channels.Channels;
import java.nio.channels.ReadableByteChannel;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.Arrays;


/**
 * An authenticator taht authenticates against the darwin system.
 */
public class DarwinAuthenticator extends AbstractAccountAuthenticator {


  private static class StaleCredentialsException extends Exception {

    private static final long serialVersionUID = 7741983680648381808L;

// Object Initialization
    public StaleCredentialsException() {
      // The exception itself is enough
    }
// Object Initialization end

  }

  @SuppressWarnings("InstanceVariableNamingConvention")
  private static class KeyInfo {

    public final long keyId;
    public final RSAPrivateKey privateKey;

// Object Initialization
    public KeyInfo(final long keyId, final RSAPrivateKey privateKey) {
      this.keyId = keyId;
      this.privateKey = privateKey;
    }
// Object Initialization end
  }

  /** The account type supported by the authenticator. */
  public static final String ACCOUNT_TYPE = "uk.ac.bournemouth.darwin.account";
  /** The token type for darwin accounts. For now there is only this type. */
  public static final String ACCOUNT_TOKEN_TYPE = "uk.ac.bournemouth.darwin.auth";
  /** The argument name used to specify the base url for authentication. */
  public static final String KEY_AUTH_BASE = "authbase";

  static final String DEFAULT_AUTH_BASE_URL = "https://darwin.bournemouth.ac.uk/accounts/";
  static final String KEY_PRIVATEKEY = "privatekey";
  static final String KEY_KEYID = "keyid";
  static final String KEY_ACCOUNT = "account";
  private static final String KEY_PUBLICKEY = "publickey";

  static final String CIPHERSUITE                  = "RSA/ECB/PKCS1Padding";
  static final String KEY_ALGORITHM                = "RSA";
  private static final int    AUTHTOKEN_RETRIEVE_TRY_COUNT = 5;

  private static final String TAG = "DarwinAuthenticator";
  private static final int CHALLENGE_MAX = 4096;
  private static final String HEADER_RESPONSE = "X-Darwin-Respond";
  private static final int MAX_TOKEN_SIZE = 1024;
  private static final int BASE64_FLAGS = Base64.URL_SAFE | Base64.NO_WRAP;
  private static final int ERRNO_INVALID_TOKENTYPE = AccountManager.ERROR_CODE_BAD_ARGUMENTS;
  private static final int ERROR_INVALID_TOKEN_SIZE = AccountManager.ERROR_CODE_BAD_AUTHENTICATION;
  private static final int ERROR_INVALID_TOKEN = AccountManager.ERROR_CODE_BAD_AUTHENTICATION;
  private static final String ERRORMSG_UNSUPPORTED_OPERATION = "Editing properties is not supported";
  private static final int ERROR_UNSUPPORTED_OPERATION = AccountManager.ERROR_CODE_UNSUPPORTED_OPERATION;
  private static final String KEY_ALLOWED_UIDS = "allowedUids";
  private static final SimpleStringSplitter COMMA_SPLITTER = new SimpleStringSplitter(',');
  private static final long EXPIRY_TIMEOUT = 1000 * 60 * 30; // 30 minutes

  private final Context mContext;

// Object Initialization

  /**
   * Create a new authenticator.
   * @param context The context used to resolve context dependent values.
   */
  public DarwinAuthenticator(final Context context) {
    super(context);
    mContext = context;
    PRNGFixes.ensureApplied();
  }
// Object Initialization end

  @Override
  public Bundle editProperties(final AccountAuthenticatorResponse response, final String accountType) {
    response.onError(ERROR_UNSUPPORTED_OPERATION, ERRORMSG_UNSUPPORTED_OPERATION);
    return null;
  }

  @Override
  public Bundle addAccount(final AccountAuthenticatorResponse response, final String accountType, final String authTokenType, final String[] requiredFeatures, final Bundle options) throws NetworkErrorException {
    Log.i(TAG, "addAccount() called with: " + "response = [" + response + "], accountType = [" + accountType + "], authTokenType = [" + authTokenType + "], requiredFeatures = [" + requiredFeatures + "], options = [" + options + "]");
    if (!(authTokenType == null || ACCOUNT_TOKEN_TYPE.equals(authTokenType))) {
      final Bundle result = new Bundle();
      result.putString(AccountManager.KEY_ERROR_MESSAGE, "invalid authTokenType");
      return result;
    }
    final Intent intent = new Intent(mContext, DarwinAuthenticatorActivity.class);
    intent.putExtra(AccountManager.KEY_ACCOUNT_AUTHENTICATOR_RESPONSE, response);
    intent.putExtra(KEY_AUTH_BASE, getAuthBase(options));
    final Bundle bundle = new Bundle();
    bundle.putParcelable(AccountManager.KEY_INTENT, intent);
    return bundle;
  }

  @Override
  public Bundle confirmCredentials(final AccountAuthenticatorResponse response, final Account account, final Bundle options) throws NetworkErrorException {
    final AccountManager am = AccountManager.get(mContext);
    final Intent intent = new Intent(mContext, DarwinAuthenticatorActivity.class);
    intent.putExtra(AccountManager.KEY_ACCOUNT_AUTHENTICATOR_RESPONSE, response);
    intent.putExtra(DarwinAuthenticatorActivity.PARAM_ACCOUNT, account);
    intent.putExtra(KEY_AUTH_BASE, am.getUserData(account, KEY_AUTH_BASE));
    intent.putExtra(DarwinAuthenticatorActivity.PARAM_CONFIRM, true);
    final long keyid = Long.parseLong(am.getUserData(account, KEY_KEYID));
    intent.putExtra(DarwinAuthenticatorActivity.PARAM_KEYID, keyid);
    final Bundle bundle = new Bundle();
    bundle.putParcelable(AccountManager.KEY_INTENT, intent);
    return bundle;
  }

  @Override
  public Bundle getAuthToken(final AccountAuthenticatorResponse response, final Account account, final String authTokenType, final Bundle options) throws NetworkErrorException {
    Log.d(TAG, "getAuthToken() called with: " + "response = [" + response + "], account = [" + account + "], authTokenType = [" + authTokenType + "], options = [" + toString(options) + "]");
    if (!authTokenType.equals(ACCOUNT_TOKEN_TYPE)) {
      response.onError(ERRNO_INVALID_TOKENTYPE, "invalid authTokenType");
      return null; // the response has the error
    }
    if (! isAuthTokenAllowed(response, account, options)) {
      return requestAuthTokenPermission(response, account, options);
    }

    final AccountManager am = AccountManager.get(mContext);
    String authBaseUrl = am.getUserData(account, KEY_AUTH_BASE);
    if (authBaseUrl == null) { authBaseUrl = DEFAULT_AUTH_BASE_URL; }

    try {
      final KeyInfo keyInfo = getKeyInfo(account);
      if (keyInfo == null || keyInfo.keyId<0) {
        // We are in an invalid state. We no longer have a private key. Redo authentication.
        initiateUpdateCredentials(account);
        return null; // The response has the data.
      }

      int tries = 0;
      while (tries < AUTHTOKEN_RETRIEVE_TRY_COUNT) {
        // Get challenge
        try {

          final Pair<URI, byte[]> challengePair = readChallenge(account, authBaseUrl, keyInfo);
          URI                     responseUrl   = challengePair.first;
          byte[]                  challenge     = challengePair.second;

          if (challenge == null) {
            initiateUpdateCredentials(account);
            return null; // The response has the data
          }

          final byte[] responseBuffer = base64encode(sign(challenge, keyInfo.privateKey));
/*
          if (BuildConfig.DEBUG) {
            Log.d(TAG, "Challenge: "+new String(challenge));
            Log.d(TAG, "Response: "+new String(responseBuffer));
            Log.d(TAG, "Private key exp: "+Base64.encodeToString(keyInfo.privateKey.getPrivateExponent().toByteArray(),0)+
                       " modulus: "+Base64.encodeToString(keyInfo.privateKey.getModulus().toByteArray(), 0));
          }
*/

          final HttpURLConnection conn = (HttpURLConnection) responseUrl.toURL().openConnection();

          try {
            writeResponse(conn, responseBuffer);
            try {
              final ReadableByteChannel in = Channels.newChannel(conn.getInputStream());
              try {
                final ByteBuffer buffer = ByteBuffer.allocate(MAX_TOKEN_SIZE);
                final int count = in.read(buffer);
                if (count < 0 || count >= MAX_TOKEN_SIZE) {
                  response.onError(ERROR_INVALID_TOKEN_SIZE, "The token size is not in a supported range");
                  return null; // the response has the error
                  // Can't handle that
                }
                final byte[] cookie = new byte[buffer.position()];
                buffer.rewind();
                buffer.get(cookie);
                for(byte b:cookie) {
                  if (! ((b>='A' && b<='Z') || (b>='a' && b<='z') ||
                         (b>='0' && b<='9') || b=='+'  || b=='/'  ||
                          b=='=' || b==' '  || b=='-'  || b=='_'  || b==':')) {
                    response.onError(ERROR_INVALID_TOKEN, "The token contains illegal characters");
                    return null;
                  }
                }

                return createResultBundle(account, cookie);


              } finally {
                in.close();
              }
            } catch (IOException e) {
              if (conn.getResponseCode() != HttpURLConnection.HTTP_UNAUTHORIZED) {
                // reauthenticate
                final Intent intent = new Intent(mContext, DarwinAuthenticatorActivity.class);
                intent.putExtra(AccountManager.KEY_ACCOUNT_AUTHENTICATOR_RESPONSE, response);
                final Bundle bundle = new Bundle();
                bundle.putParcelable(AccountManager.KEY_INTENT, intent);
                return bundle;

              } else if (conn.getResponseCode() != HttpURLConnection.HTTP_NOT_FOUND) { // We try again if we didn't get the right code.
                final Bundle result = new Bundle();
                result.putInt(AccountManager.KEY_ERROR_CODE, conn.getResponseCode());
                result.putString(AccountManager.KEY_ERROR_MESSAGE, e.getMessage());
                return result;
              }
            }
          } finally {
            conn.disconnect();
          }

        } catch (MalformedURLException e) {
          e.printStackTrace(); // Should never happen, it's a constant
        } catch (IOException e) {
          throw new NetworkErrorException(e);
        }
        ++tries;
      }
      final Bundle result = new Bundle();
      result.putString(AccountManager.KEY_ERROR_MESSAGE, "Could not get authentication key");
      return result;
    } catch (StaleCredentialsException e) {
      final Bundle result = new Bundle();
      result.putParcelable(AccountManager.KEY_INTENT, getUpdateCredentialsBaseIntent(account, authBaseUrl));
      return result;
    }
  }

  static String toString(final Bundle options) {
    StringBuilder b = new StringBuilder();
    b.append('[');
    boolean first = true;
    for(String key: options.keySet()) {
      if (first) {
        first = false;
      } else {
        b.append(", ");
      }
      b.append(key).append('=').append(options.get(key));
    }
    b.append(']');
    return b.toString();
  }

  private Bundle requestAuthTokenPermission(final AccountAuthenticatorResponse response, final Account account, final Bundle options) {
    Intent intent = new Intent(mContext, AuthTokenPermissionActivity.class);
    intent.putExtra(KEY_ACCOUNT, account);
    intent.putExtra(AccountManager.KEY_CALLER_UID, options.getInt(AccountManager.KEY_CALLER_UID));
    intent.putExtra(AccountManager.KEY_ANDROID_PACKAGE_NAME, options.getString(AccountManager.KEY_ANDROID_PACKAGE_NAME));

    Bundle b = new Bundle(1);
    b.putParcelable(AccountManager.KEY_INTENT, intent);
    response.onResult(b);
    return b;
  }

  static boolean isAllowedUid(AccountManager am, Account account, int uid, final String callerPackage) {
    String allowedUidsString = am.getUserData(account, KEY_ALLOWED_UIDS);
    Log.d(TAG, "isAllowedUid() called with: " + "am = [" + am + "], account = [" + account + "], uid = [" + uid + "], callerPackage = [" + callerPackage + "], allowedUidString=["+allowedUidsString+"]");
    if (allowedUidsString==null || allowedUidsString.isEmpty()) { return false; }
    COMMA_SPLITTER.setString(allowedUidsString);
    for(String s:COMMA_SPLITTER) {
      int allowedUid = Integer.parseInt(s.trim());
      if (allowedUid==uid) {
        Log.d(TAG, "isAllowedUid() returned: true");
        return true;
      }
    }
    Log.d(TAG, "isAllowedUid() returned: false");
    return false;
  }

  static void addAllowedUid(AccountManager am, Account account, int uid) {
    String allowedUidsString = am.getUserData(account, KEY_ALLOWED_UIDS);
    if (allowedUidsString==null || allowedUidsString.isEmpty()) {
      allowedUidsString = Integer.toString(uid);
    } else {
      COMMA_SPLITTER.setString(allowedUidsString);
      for (String s : COMMA_SPLITTER) {
        int allowedUid = Integer.parseInt(s.trim());
        if (allowedUid == uid) { return; } // already stored, bail out
      }
      allowedUidsString = allowedUidsString + "," + Integer.toString(uid);
    }
    am.setUserData(account, KEY_ALLOWED_UIDS, allowedUidsString);
  }

  static void removeAllowedUid(AccountManager am, Account account, int uid) {
    String allowedUidsString = am.getUserData(account, KEY_ALLOWED_UIDS);
    String uidString = Integer.toString(uid);
    Log.d(TAG, "removeAllowedUid() called with: " + "am = [" + am + "], account = [" + account + "], uid = [" + uid + "], allowedUids=["+allowedUidsString+"], uidString=["+uidString+"]");
    if (allowedUidsString==null || allowedUidsString.isEmpty()) {
      return;
    } else {
      String newString = null;
      for(int i=allowedUidsString.indexOf(uidString); i>=0;i=allowedUidsString.indexOf(uidString,i+1)) {
        final int afterUid = i + uidString.length();
        char before = i==0 ? ',' : allowedUidsString.charAt(i-1);
        char after = afterUid >= allowedUidsString.length() ? ',' : allowedUidsString.charAt(afterUid);
        if (before==',' && after==',') {
          if (i>0) { newString = allowedUidsString.substring(0, i-1); } else { newString=""; }
          if (afterUid+1<allowedUidsString.length()) { newString = newString.concat(allowedUidsString.substring(afterUid)); }
        }
        // do not break in case of duplication.
      }
      if (newString==null) { return; }
      am.setUserData(account, KEY_ALLOWED_UIDS, newString);
      Log.d(TAG, "removeAllowedUid("+uid+") stored: " + newString + " was:" +allowedUidsString);
    }
  }

  private boolean isAuthTokenAllowed(final AccountAuthenticatorResponse response, final Account account, final Bundle options) {
    Log.d(TAG, "isAuthTokenAllowed() called with: " + "response = [" + response + "], account = [" + account + "], options = " + options + ", myUid=["+Process.myUid()+"]");
    if (! options.containsKey(AccountManager.KEY_CALLER_UID)) { return true; /* customTokens disabled */ }
    int callerUid = options.getInt(AccountManager.KEY_CALLER_UID, -1);
    String callerPackage = options.getString(AccountManager.KEY_ANDROID_PACKAGE_NAME);
    if (Process.myUid()==callerUid) { return true; }
    AccountManager am = AccountManager.get(mContext);
    return isAllowedUid(am, account, callerUid, callerPackage);
  }

  private static int[] toInts(final String[] strings) {
    int[] result = new int[strings.length];
    for (int i = 0; i < strings.length; i++) {
      result[i] = Integer.parseInt(strings[i]);
    }
    return result;
  }

  private static Bundle createResultBundle(final Account account, final byte[] cookie) {
    final Bundle result = new Bundle(3);
    result.putString(AccountManager.KEY_ACCOUNT_NAME, account.name);
    result.putString(AccountManager.KEY_ACCOUNT_TYPE, ACCOUNT_TOKEN_TYPE);
    result.putString(AccountManager.KEY_AUTHTOKEN, new String(cookie, Util.UTF8));
    result.putLong(KEY_CUSTOM_TOKEN_EXPIRY, System.currentTimeMillis()+EXPIRY_TIMEOUT);
    return result;
  }

  private KeyInfo getKeyInfo(final Account account) {
    final AccountManager am = AccountManager.get(mContext);
    final String privateKeyString = am.getUserData(account, KEY_PRIVATEKEY);
    if (privateKeyString==null) { return null; }
    final RSAPrivateKey privateKey = getPrivateKey(privateKeyString);
    final String keyidString = am.getUserData(account, KEY_KEYID);
    final long keyId = keyidString == null ? -1L : Long.parseLong(keyidString);
    if (privateKeyString == null || keyidString == null) { return null; }
    return new KeyInfo(keyId, privateKey);
  }

  private static RSAPrivateKey getPrivateKey(final String privateKeyString) {
    final KeyFactory keyfactory;
    try {
      keyfactory = KeyFactory.getInstance(KEY_ALGORITHM);
    } catch (NoSuchAlgorithmException e) {
      Log.e(TAG, "The RSA algorithm isn't supported on your system", e);
      return null;
    }
    final KeySpec keyspec;
    {
      final int end = privateKeyString.indexOf(':');
      final BigInteger modulus = new BigInteger(privateKeyString.substring(0, end));

      final int start = end + 1;
      final BigInteger privateExponent = new BigInteger(privateKeyString.substring(start));
      keyspec = new RSAPrivateKeySpec(modulus, privateExponent);
    }
    try {
      return (RSAPrivateKey) keyfactory.generatePrivate(keyspec);
    } catch (InvalidKeySpecException e) {
      Log.w(TAG, "Could not load private key", e);
      return null;
    }
  }

  private static byte[] sign(final byte[] challenge, final RSAPrivateKey privateKey) {
    final Cipher cipher;
    try {
      cipher = Cipher.getInstance(CIPHERSUITE);
      cipher.init(Cipher.ENCRYPT_MODE, privateKey);

      // Prepare the output buffer for reading.
      byte[] response = cipher.doFinal(challenge);
/*
      if (BuildConfig.DEBUG) {
        KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
        RSAPublicKey publicKey = (RSAPublicKey) keyFactory.generatePublic(new RSAPublicKeySpec(privateKey.getModulus(), BigInteger.valueOf(65537)));
        cipher.init(Cipher.DECRYPT_MODE, publicKey);
        byte[] challengeCopy = cipher.doFinal(response);
        Log.e(TAG, "Validated response: "+new String(Base64.encodeToString(response,0)));
        Log.e(TAG, "Copy of challenge: "+new String(challengeCopy));
        if (!Arrays.equals(challenge, challengeCopy)) {
          throw new IllegalStateException("The challenge and its copy are different");
        }
      }
*/
      return response;
    } catch (GeneralSecurityException e) {
      Log.w(TAG, e);
      return null;
    }
  }

  private static void writeResponse(final HttpURLConnection conn, final byte[] response) throws IOException {
    conn.setDoOutput(true);
    conn.setRequestMethod("POST");
    conn.setRequestProperty("Content-Type", "application/x-www-form-urlencoded;charset=utf8");
    final OutputStream out = conn.getOutputStream();
    try {
      out.write("response=".getBytes());
      out.write(response);
    } finally {
      out.close();
    }
  }

  private static byte[] base64encode(final byte[] in) {
    return Base64.encode(in, BASE64_FLAGS);
  }

  private static void initiateUpdateCredentials(final Account account) throws StaleCredentialsException {
    throw new StaleCredentialsException();
  }

  private static Pair<URI, byte[]> readChallenge(final Account account, final String authBaseUrl, final KeyInfo keyInfo) throws IOException, StaleCredentialsException {
    URI responseUrl;
    final URI url = URI.create(getChallengeUrl(authBaseUrl).toString() + "?keyid=" + keyInfo.keyId);
    final HttpURLConnection connection = (HttpURLConnection) url.toURL().openConnection();
    connection.setInstanceFollowRedirects(false);// We should get the response url.
    try {
      {
        final String header = connection.getHeaderField(HEADER_RESPONSE);
        responseUrl = header == null ? url : URI.create(header);
      }

      final int responseCode = connection.getResponseCode();
      if (responseCode == HttpURLConnection.HTTP_FORBIDDEN || responseCode==HttpURLConnection.HTTP_NOT_FOUND) {
        initiateUpdateCredentials(account);
      } else if (responseCode >= 400) {
        throw new HttpResponseException(connection);
      }

      byte[] inBuffer = new byte[(CHALLENGE_MAX*4)/3];

      final InputStream in = connection.getInputStream();
      final int readCount;
      try {
        readCount = in.read(inBuffer);
      } finally {
        in.close();
      }
      byte[] decodedChallenge = Base64.decode(inBuffer, 0, readCount, Base64.DEFAULT);

      return Pair.create(responseUrl, decodedChallenge);
    } finally {
      connection.disconnect();
    }
  }

  @SuppressWarnings("StringConcatenationMissingWhitespace")
  private static URI getChallengeUrl(final String authBaseUrl) {
    return URI.create(authBaseUrl + "challenge");
  }

  @Override
  public String getAuthTokenLabel(final String authTokenType) {
    Log.i(TAG, "Getting token label");
    if (!authTokenType.equals(ACCOUNT_TOKEN_TYPE)) {
      return null;
    }
    return mContext.getString(R.string.authtoken_label);
  }

  @Override
  public Bundle updateCredentials(final AccountAuthenticatorResponse response, final Account account, final String authTokenType, final Bundle options) throws NetworkErrorException {
    final AccountManager am = AccountManager.get(mContext);
    final String authbase = am.getUserData(account, KEY_AUTH_BASE);
    final Intent intent = getUpdateCredentialsBaseIntent(account, authbase);
    intent.putExtra(AccountManager.KEY_ACCOUNT_AUTHENTICATOR_RESPONSE, response);
    final long keyid = Long.parseLong(am.getUserData(account, KEY_KEYID));
    intent.putExtra(DarwinAuthenticatorActivity.PARAM_KEYID, keyid);
    final Bundle bundle = new Bundle();
    bundle.putParcelable(AccountManager.KEY_INTENT, intent);
    return bundle;
  }

  private Intent getUpdateCredentialsBaseIntent(final Account account, final String authBaseUrl) {
    final Intent intent = new Intent(mContext, DarwinAuthenticatorActivity.class);
    intent.putExtra(DarwinAuthenticatorActivity.PARAM_ACCOUNT, account);
    intent.putExtra(DarwinAuthenticatorActivity.PARAM_CONFIRM, false);
    intent.putExtra(DarwinAuthenticator.KEY_AUTH_BASE, authBaseUrl);
    return intent;
  }

  @Override
  public Bundle hasFeatures(final AccountAuthenticatorResponse response, final Account account, final String[] features) throws NetworkErrorException {
    Log.i(TAG, "hasFeatures() called with: " + "response = [" + response + "], account = [" + account + "], features = [" + features + "]");
    final boolean hasFeature;
    if (features.length == 1) {
      final AccountManager am = AccountManager.get(mContext);
      final String authbase = am.getUserData(account, KEY_AUTH_BASE);
      if (authbase == null) {
        hasFeature = features[0] == null || DEFAULT_AUTH_BASE_URL.equals(features[0]);
      } else {
        hasFeature = authbase.equals(features[0]) || (features[0] == null && DEFAULT_AUTH_BASE_URL.equals(authbase));
      }
    } else {
      hasFeature = false;
    }
    final Bundle result = new Bundle();
    result.putBoolean(AccountManager.KEY_BOOLEAN_RESULT, hasFeature);
    Log.i(TAG, "hasFeatures() returned: " + result+ " -> "+hasFeature);
    return result;
  }

  private static String getAuthBase(final Bundle options) {
    String authBaseUrl = options.getString(KEY_AUTH_BASE);
    if (authBaseUrl == null) { authBaseUrl = DEFAULT_AUTH_BASE_URL; }
    return authBaseUrl;
  }

  @SuppressWarnings("StringConcatenationMissingWhitespace")
  static URI getAuthenticateUrl(final String authBaseUrl) {
    return URI.create(authBaseUrl + "regkey");
  }

  static String encodePrivateKey(final RSAPrivateKey privateKey) {
    final StringBuilder result = new StringBuilder();
    result.append(privateKey.getModulus());
    result.append(':');
    result.append(privateKey.getPrivateExponent());
    return result.toString();
  }

  static String encodePublicKey(final RSAPublicKey publicKey) {
    final StringBuilder result = new StringBuilder();
    result.append(Base64.encodeToString(publicKey.getModulus().toByteArray(), BASE64_FLAGS));
    result.append(':');
    result.append(Base64.encodeToString(publicKey.getPublicExponent().toByteArray(), BASE64_FLAGS));
    if (Log.isLoggable(TAG, Log.DEBUG)) {
      Log.d(TAG, "Registering public key: (" + publicKey.getModulus() + ", " + publicKey.getPublicExponent() + ')' + result);
    }
    return result.toString();
  }
}