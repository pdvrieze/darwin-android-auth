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
import android.util.Base64;
import android.util.Log;

import javax.crypto.Cipher;

import java.io.IOException;
import java.math.BigInteger;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URI;
import java.nio.ByteBuffer;
import java.nio.channels.Channels;
import java.nio.channels.ReadableByteChannel;
import java.nio.channels.WritableByteChannel;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.RSAPrivateKeySpec;


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
  private static final String KEY_PUBLICKEY = "publickey";
  static final String KEY_ALGORITHM = "RSA";

  private static final int AUTHTOKEN_RETRIEVE_TRY_COUNT = 5;
  private static final String TAG = DarwinAuthenticator.class.getName();
  private static final int CHALLENGE_MAX = 4096;
  private static final String HEADER_RESPONSE = "X-Darwin-Respond";
  private static final int MAX_TOKEN_SIZE = 1024;
  private static final int BASE64_FLAGS = Base64.URL_SAFE | Base64.NO_WRAP;
  private static final int ERRNO_INVALID_TOKENTYPE = AccountManager.ERROR_CODE_BAD_ARGUMENTS;
  private static final int ERROR_INVALID_TOKEN_SIZE = AccountManager.ERROR_CODE_BAD_AUTHENTICATION;
  private static final String ERRORMSG_UNSUPPORTED_OPERATION = "Editing properties is not supported";
  private static final int ERROR_UNSUPPORTED_OPERATION = AccountManager.ERROR_CODE_UNSUPPORTED_OPERATION;

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
    if (!authTokenType.equals(ACCOUNT_TOKEN_TYPE)) {
      response.onError(ERRNO_INVALID_TOKENTYPE, "invalid authTokenType");
      return null; // the response has the error
    }
    final AccountManager am = AccountManager.get(mContext);
    String authBaseUrl = am.getUserData(account, KEY_AUTH_BASE);
    if (authBaseUrl == null) { authBaseUrl = DEFAULT_AUTH_BASE_URL; }

    try {
      final KeyInfo keyInfo = getKeyInfo(account);
      if (keyInfo == null) {
        // We are in an invalid state. We no longer have a private key. Redo authentication.
        initiateUpdateCredentials();
        return null; // The response has the data.
      }

      int tries = 0;
      while (tries < AUTHTOKEN_RETRIEVE_TRY_COUNT) {
        // Get challenge
        try {

          final ByteBuffer challenge = ByteBuffer.allocate(CHALLENGE_MAX);
          final URI responseUrl = readChallenge(authBaseUrl, keyInfo, challenge);
          if (challenge == null) {
            initiateUpdateCredentials();
            return null; // The response has the data
          }

          final ByteBuffer responseBuffer = base64encode(sign(challenge, keyInfo.privateKey));

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
      result.putParcelable(AccountManager.KEY_INTENT, getUpdateCredentialsBaseIntent(account));
      return result;
    }
  }

  private static Bundle createResultBundle(final Account account, final byte[] cookie) {
    final Bundle result = new Bundle(3);
    result.putString(AccountManager.KEY_ACCOUNT_NAME, account.name);
    result.putString(AccountManager.KEY_ACCOUNT_TYPE, ACCOUNT_TOKEN_TYPE);
    result.putString(AccountManager.KEY_AUTHTOKEN, new String(cookie, Util.UTF8));
    return result;
  }

  private KeyInfo getKeyInfo(final Account account) {
    final AccountManager am = AccountManager.get(mContext);
    final String privateKeyString = am.getUserData(account, KEY_PRIVATEKEY);
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
      Log.e(TAG, "The DSA algorithm isn't supported on your system", e);
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

  private static ByteBuffer sign(final ByteBuffer challenge, final RSAPrivateKey privateKey) {
    final Cipher cipher;
    try {
      cipher = Cipher.getInstance("RSA");
      cipher.init(Cipher.ENCRYPT_MODE, privateKey);

      final ByteBuffer output = ByteBuffer.allocate(cipher.getOutputSize(challenge.limit()));

      cipher.doFinal(challenge, output);

      // Prepare the output buffer for reading.
      output.limit(output.position());
      output.rewind();
      return output;
    } catch (GeneralSecurityException e) {
      Log.w(TAG, e);
      return null;
    }
  }

  private static void writeResponse(final HttpURLConnection conn, final ByteBuffer response) throws IOException {
    conn.setDoOutput(true);
    conn.setRequestMethod("POST");
    conn.setRequestProperty("Content-Type", "application/x-www-form-urlencoded;charset=utf8");
    final WritableByteChannel out = Channels.newChannel(conn.getOutputStream());
    try {
      out.write(ByteBuffer.wrap(new byte[]{'r', 'e', 's', 'p', 'o', 'n', 's', 'e', '='}));
      out.write(response);
    } finally {
      out.close();
    }
  }

  private static ByteBuffer base64encode(final ByteBuffer in) {
    return ByteBuffer.wrap(Base64.encode(in.array(), in.arrayOffset(), in.remaining(), BASE64_FLAGS));
  }

  private static void initiateUpdateCredentials() throws StaleCredentialsException {
    throw new StaleCredentialsException();
  }

  private static URI readChallenge(final String authBaseUrl, final KeyInfo keyInfo, final ByteBuffer out) throws IOException, StaleCredentialsException {
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
      if (responseCode == 403) {
        initiateUpdateCredentials();
      } else if (responseCode >= 400) {
        throw new HttpResponseException(connection);
      }

      final ReadableByteChannel in = Channels.newChannel(connection.getInputStream());
      try {
        in.read(out);
      } finally {
        in.close();
      }
      out.limit(out.position());
      out.rewind();
    } finally {
      connection.disconnect();
    }
    return responseUrl;
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
    return mContext.getString(R.string.authenticator_label);
  }

  @Override
  public Bundle updateCredentials(final AccountAuthenticatorResponse response, final Account account, final String authTokenType, final Bundle options) throws NetworkErrorException {
    final Intent intent = getUpdateCredentialsBaseIntent(account);
    intent.putExtra(AccountManager.KEY_ACCOUNT_AUTHENTICATOR_RESPONSE, response);
    final AccountManager am = AccountManager.get(mContext);
    final long keyid = Long.parseLong(am.getUserData(account, KEY_KEYID));
    intent.putExtra(DarwinAuthenticatorActivity.PARAM_KEYID, keyid);
    intent.putExtra(KEY_AUTH_BASE, am.getUserData(account, KEY_AUTH_BASE));
    intent.putExtra(DarwinAuthenticatorActivity.PARAM_ACCOUNT, account);
    final Bundle bundle = new Bundle();
    bundle.putParcelable(AccountManager.KEY_INTENT, intent);
    return bundle;
  }

  private Intent getUpdateCredentialsBaseIntent(final Account account) {
    final Intent intent = new Intent(mContext, DarwinAuthenticatorActivity.class);
    intent.putExtra(DarwinAuthenticatorActivity.PARAM_ACCOUNT, account);
    intent.putExtra(DarwinAuthenticatorActivity.PARAM_CONFIRM, false);
    return intent;
  }

  @Override
  public Bundle hasFeatures(final AccountAuthenticatorResponse response, final Account account, final String[] features) throws NetworkErrorException {
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
    if (BuildConfig.DEBUG) {
      Log.d(TAG, "Registering public key: (" + publicKey.getModulus() + ", " + publicKey.getPublicExponent() + ')' + result);
    }
    return result.toString();
  }
}