package uk.ac.bournemouth.darwin.auth;

import android.accounts.AbstractAccountAuthenticator;
import android.accounts.Account;
import android.accounts.AccountAuthenticatorResponse;
import android.accounts.NetworkErrorException;
import android.content.Context;
import android.content.Intent;
import android.os.Bundle;


public class DarwinAuthenticator extends AbstractAccountAuthenticator {
  
  public static final String ACCOUNT_TYPE="uk.ac.bournemouth.darwin.auth";
  private Context aContext;

  public DarwinAuthenticator(Context pContext) {
    super(pContext);
    aContext = pContext;
  }

  @Override
  public Bundle addAccount(AccountAuthenticatorResponse pResponse, String pAccountType, String pAuthTokenType, String[] pRequiredFeatures, Bundle pOptions) throws NetworkErrorException {
    final Intent intent = new Intent(aContext, DarwinAuthenticatorActivity.class);
    // TODO Auto-generated method stub
    return null;
  }

  @Override
  public Bundle confirmCredentials(AccountAuthenticatorResponse pResponse, Account pAccount, Bundle pOptions) throws NetworkErrorException {
    // TODO Auto-generated method stub
    return null;
  }

  @Override
  public Bundle editProperties(AccountAuthenticatorResponse pResponse, String pAccountType) {
    // TODO Auto-generated method stub
    return null;
  }

  @Override
  public Bundle getAuthToken(AccountAuthenticatorResponse pResponse, Account pAccount, String pAuthTokenType, Bundle pOptions) throws NetworkErrorException {
    // TODO Auto-generated method stub
    return null;
  }

  @Override
  public String getAuthTokenLabel(String pAuthTokenType) {
    // TODO Auto-generated method stub
    return null;
  }

  @Override
  public Bundle hasFeatures(AccountAuthenticatorResponse pResponse, Account pAccount, String[] pFeatures) throws NetworkErrorException {
    // TODO Auto-generated method stub
    return null;
  }

  @Override
  public Bundle updateCredentials(AccountAuthenticatorResponse pResponse, Account pAccount, String pAuthTokenType, Bundle pOptions) throws NetworkErrorException {
    // TODO Auto-generated method stub
    return null;
  }

}
