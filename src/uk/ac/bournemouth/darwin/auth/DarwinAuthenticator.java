package uk.ac.bournemouth.darwin.auth;

import java.io.IOException;
import java.math.BigInteger;
import java.net.MalformedURLException;
import java.net.ProtocolException;
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

import javax.crypto.Cipher;
import javax.net.ssl.HttpsURLConnection;

import android.accounts.*;
import android.content.Context;
import android.content.Intent;
import android.os.Bundle;
import android.util.Base64;
import android.util.Log;


public class DarwinAuthenticator extends AbstractAccountAuthenticator {
  
  
  private static class StaleCredentialsException extends Exception {

    public StaleCredentialsException() {
      // The exception itself is enough
    }

  }

  private static class KeyInfo {
    public long keyId=-1l;
    public RSAPrivateKey privateKey;

    public KeyInfo(long pKeyId, RSAPrivateKey pPrivateKey) {
      keyId = pKeyId;
      privateKey = pPrivateKey;
    }
  }
  
  private static final int AUTHTOKEN_RETRIEVE_TRY_COUNT = 5;
  private static final String AUTH_BASE_URL = "https://darwin.bournemouth.ac.uk/accounts/";
  public static final String ACCOUNT_TOKEN_TYPE="uk.ac.bournemouth.darwin.auth";
  static final String KEY_PRIVATEKEY = "privatekey";
  static final String KEY_KEYID = "keyid";
  static final String KEY_PUBLICKEY = "publickey";
  private static final String TAG = DarwinAuthenticator.class.getName();
  static final String KEY_ALGORITHM = "RSA";
  static final URI GET_CHALLENGE_URL = URI.create(AUTH_BASE_URL+"challenge");
  static final URI AUTHENTICATE_URL = URI.create(AUTH_BASE_URL+"regkey");
  private static final int CHALLENGE_MAX = 4096;
  private static final String HEADER_RESPONSE = "X-Darwin-Respond";
  private static final int MAX_TOKEN_SIZE = 1024;
  private static final int BASE64_FLAGS = Base64.URL_SAFE|Base64.NO_WRAP;
  public static final String ACCOUNT_TYPE = "darwin";
  private static final int ERRNO_INVALID_TOKENTYPE = 1;
  private Context aContext;

  public DarwinAuthenticator(Context pContext) {
    super(pContext);
    aContext = pContext;
  }

  @Override
  public Bundle addAccount(AccountAuthenticatorResponse pResponse, String pAccountType, String pAuthTokenType, String[] pRequiredFeatures, Bundle pOptions) throws NetworkErrorException {
    if (!(pAuthTokenType==null || ACCOUNT_TOKEN_TYPE.equals(pAuthTokenType))) {
      final Bundle result = new Bundle();
      result.putString(AccountManager.KEY_ERROR_MESSAGE, "invalid authTokenType");
      return result;
    }
    final Intent intent = new Intent(aContext, DarwinAuthenticatorActivity.class);
    intent.putExtra(AccountManager.KEY_ACCOUNT_AUTHENTICATOR_RESPONSE, pResponse);
    final Bundle bundle = new Bundle();
    bundle.putParcelable(AccountManager.KEY_INTENT, intent);
    return bundle;
  }

  @Override
  public Bundle confirmCredentials(AccountAuthenticatorResponse pResponse, Account pAccount, Bundle pOptions) throws NetworkErrorException {
    final Intent intent = new Intent(aContext, DarwinAuthenticatorActivity.class);
    intent.putExtra(AccountManager.KEY_ACCOUNT_AUTHENTICATOR_RESPONSE, pResponse);
    intent.putExtra(DarwinAuthenticatorActivity.PARAM_USERNAME, pAccount.name);
    intent.putExtra(DarwinAuthenticatorActivity.PARAM_CONFIRM, true);
    AccountManager am=AccountManager.get(aContext);
    long keyid=Long.parseLong(am.getUserData(pAccount, KEY_KEYID));
    intent.putExtra(DarwinAuthenticatorActivity.PARAM_KEYID, keyid);
    final Bundle bundle = new Bundle();
    bundle.putParcelable(AccountManager.KEY_INTENT, intent);
    return bundle;
  }

  
  
  @Override
  public Bundle updateCredentials(AccountAuthenticatorResponse pResponse, Account pAccount, String pAuthTokenType, Bundle pOptions) throws NetworkErrorException {
    final Intent intent = getUpdateCredentialsBaseIntent(pAccount);
    intent.putExtra(AccountManager.KEY_ACCOUNT_AUTHENTICATOR_RESPONSE, pResponse);
    AccountManager am=AccountManager.get(aContext);
    long keyid=Long.parseLong(am.getUserData(pAccount, KEY_KEYID));
    intent.putExtra(DarwinAuthenticatorActivity.PARAM_KEYID, keyid);
    final Bundle bundle = new Bundle();
    bundle.putParcelable(AccountManager.KEY_INTENT, intent);
    return bundle;
  }

  private Intent getUpdateCredentialsBaseIntent(Account pAccount) {
    final Intent intent = new Intent(aContext, DarwinAuthenticatorActivity.class);
    intent.putExtra(DarwinAuthenticatorActivity.PARAM_USERNAME, pAccount.name);
    intent.putExtra(DarwinAuthenticatorActivity.PARAM_CONFIRM, false);
    return intent;
  }

  @Override
  public Bundle editProperties(AccountAuthenticatorResponse pResponse, String pAccountType) {
    // TODO Auto-generated method stub
    throw new UnsupportedOperationException();
  }

  @Override
  public Bundle getAuthToken(AccountAuthenticatorResponse pResponse, Account pAccount, String pAuthTokenType, Bundle pOptions) throws NetworkErrorException {
    if (!pAuthTokenType.equals(ACCOUNT_TOKEN_TYPE)) {
      pResponse.onError(ERRNO_INVALID_TOKENTYPE, "invalid authTokenType");
      return null;
    }
    
    try {
      KeyInfo keyInfo = getKeyInfo(pAccount);
      if (keyInfo==null) {
        // We are in an invalid state. We no longer have a private key. Redo authentication.
        initiateUpdateCredentials();
      }
      
      int tries=0;
      while (tries<AUTHTOKEN_RETRIEVE_TRY_COUNT) {
        // Get challenge
        try {
          
          ByteBuffer challenge = ByteBuffer.allocate(CHALLENGE_MAX);
          URI responseUrl = readChallenge(keyInfo, challenge);
          if (challenge == null) {
            initiateUpdateCredentials(); //return null; // return to shut up compiler
          }
          
          final ByteBuffer response = base64encode(sign(challenge, keyInfo.privateKey));

          HttpsURLConnection conn = (HttpsURLConnection) responseUrl.toURL().openConnection();
          
          try {
            writeResponse(conn, response);
            try {
              ReadableByteChannel in = Channels.newChannel(conn.getInputStream());
              try {
                ByteBuffer buffer =ByteBuffer.allocate(MAX_TOKEN_SIZE);
                int count = in.read(buffer);
                if (count<0 || count>=MAX_TOKEN_SIZE) {
                  // Can't handle that
                }
                byte[] cookie = new byte[buffer.position()];
                buffer.rewind();
                buffer.get(cookie);
                
                Bundle result = new Bundle();
                result.putString(AccountManager.KEY_ACCOUNT_NAME, pAccount.name);
                result.putString(AccountManager.KEY_ACCOUNT_TYPE, ACCOUNT_TOKEN_TYPE);
                result.putString(AccountManager.KEY_AUTHTOKEN, new String(cookie, Util.UTF8));
                return result;
                
                
                
              } finally {
                in.close();
              }
            } catch (IOException e) {
              if (conn.getResponseCode()!=401) {
                // reauthenticate
                final Intent intent = new Intent(aContext, DarwinAuthenticatorActivity.class);
                intent.putExtra(AccountManager.KEY_ACCOUNT_AUTHENTICATOR_RESPONSE, pResponse);
                final Bundle bundle = new Bundle();
                bundle.putParcelable(AccountManager.KEY_INTENT, intent);
                return bundle;
                
              }else if (conn.getResponseCode()!=404) { // We try again if we didn't get the right code.
                Bundle result = new Bundle();
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
      Bundle result = new Bundle();
      result.putString(AccountManager.KEY_ERROR_MESSAGE, "Could not get authentication key");
      return result;
    } catch (StaleCredentialsException e) {
      Bundle result = new Bundle();
      result.putParcelable(AccountManager.KEY_INTENT, getUpdateCredentialsBaseIntent(pAccount));
      return result;
    }
  }

  private KeyInfo getKeyInfo(Account pAccount) {
    final AccountManager am = AccountManager.get(aContext);
    String privateKeyString = am.getUserData(pAccount, KEY_PRIVATEKEY);
    RSAPrivateKey privateKey = getPrivateKey(privateKeyString);
    String keyidString = am.getUserData(pAccount, KEY_KEYID);
    long keyId = keyidString==null ? -1l : Long.parseLong(keyidString);
    if (privateKeyString==null || keyidString==null) { return null; }
    return new KeyInfo(keyId, privateKey);
  }

  private ByteBuffer sign(ByteBuffer pChallenge, RSAPrivateKey pPrivateKey) {
    Cipher cipher;
    try {
      cipher = Cipher.getInstance("RSA");
      cipher.init(Cipher.ENCRYPT_MODE, pPrivateKey);
      
      ByteBuffer output = ByteBuffer.allocate(cipher.getOutputSize(pChallenge.limit()));
      
      cipher.doFinal(pChallenge, output);
      
      // Prepare the output buffer for reading.
      output.limit(output.position());
      output.rewind();
      return output;
    } catch (GeneralSecurityException e) {
      Log.w(TAG, e);
      return null;
    }
  }

  private void writeResponse(HttpsURLConnection conn, final ByteBuffer response) throws ProtocolException, IOException {
    conn.setDoOutput(true);
    conn.setRequestMethod("POST");
    conn.setRequestProperty("Content-Type", "application/x-www-form-urlencoded;charset=utf8");
    WritableByteChannel out = Channels.newChannel(conn.getOutputStream());
    try {
      out.write(ByteBuffer.wrap(new byte[] {'r','e','s','p','o','n','s','e','='}));
      out.write(response);
    } finally {
      out.close();
    }
  }

  private static ByteBuffer base64encode(ByteBuffer in) {
    return ByteBuffer.wrap(Base64.encode(in.array(), in.arrayOffset(), in.remaining(), BASE64_FLAGS));
  }

  private void initiateUpdateCredentials() throws StaleCredentialsException {
    throw new StaleCredentialsException();
  }

  private URI readChallenge(KeyInfo pKeyInfo, ByteBuffer out) throws IOException, StaleCredentialsException {
    URI responseUrl;
    final URI url = URI.create(GET_CHALLENGE_URL.toString()+"?keyid="+pKeyInfo.keyId);
    HttpsURLConnection c = (HttpsURLConnection) url.toURL().openConnection();
    c.setInstanceFollowRedirects(false);// We should get the response url.
    try {
      {
        String header = c.getHeaderField(HEADER_RESPONSE);
        responseUrl = header==null ? url : URI.create(header);
      }
      
      int responseCode = c.getResponseCode();
      if (responseCode==403) {
        initiateUpdateCredentials();
      } else if (responseCode>=400) {
        throw new HttpResponseException(c);
      }
      
      ReadableByteChannel in = Channels.newChannel(c.getInputStream());
      try {
        in.read(out);
      } finally {
        in.close();
      }
      out.limit(out.position());
      out.rewind();
    } finally {
      c.disconnect();
    }
    return responseUrl;
  }

  private static RSAPrivateKey getPrivateKey(String pPrivateKeyString) {
    KeyFactory keyfactory;
    try {
      keyfactory = KeyFactory.getInstance(KEY_ALGORITHM);
    } catch (NoSuchAlgorithmException e) {
      Log.e(TAG, "The DSA algorithm isn't supported on your system", e);
      return null;
    }
    KeySpec keyspec;
    {
      int start = 0;
      int end = pPrivateKeyString.indexOf(':');
      BigInteger modulus= new BigInteger(pPrivateKeyString.substring(start, end));
      start = end+1;
      BigInteger privateExponent=new BigInteger(pPrivateKeyString.substring(start));;
      keyspec = new RSAPrivateKeySpec(modulus, privateExponent);
    }
    try {
      return (RSAPrivateKey) keyfactory.generatePrivate(keyspec);
    } catch (InvalidKeySpecException e) {
      Log.w(TAG, "Could not load private key", e);
      return null;
    }
  }
  
  static String encodePrivateKey(RSAPrivateKey pPrivateKey) {
    StringBuilder result = new StringBuilder();
    result.append(pPrivateKey.getModulus());
    result.append(':');
    result.append(pPrivateKey.getPrivateExponent());
    return result.toString();
  }
  
  static String encodePublicKey(RSAPublicKey pPublicKey) {
    StringBuilder result = new StringBuilder();
    result.append(Base64.encodeToString(pPublicKey.getModulus().toByteArray(), BASE64_FLAGS));
    result.append(':');
    result.append(Base64.encodeToString(pPublicKey.getPublicExponent().toByteArray(), BASE64_FLAGS));
    if (BuildConfig.DEBUG) {
      Log.d(TAG, "Registering public key: ("+pPublicKey.getModulus()+", "+pPublicKey.getPublicExponent()+")"+result);
    }
    return result.toString();
  }

  @Override
  public String getAuthTokenLabel(String pAuthTokenType) {
    if (!pAuthTokenType.equals(ACCOUNT_TOKEN_TYPE)) {
      return null;
    }
    return aContext.getString(R.string.authenticator_label);
  }

  @Override
  public Bundle hasFeatures(AccountAuthenticatorResponse pResponse, Account pAccount, String[] pFeatures) throws NetworkErrorException {
    final Bundle result = new Bundle();
    result.putBoolean(AccountManager.KEY_BOOLEAN_RESULT, false);
    return result;
  }

}
