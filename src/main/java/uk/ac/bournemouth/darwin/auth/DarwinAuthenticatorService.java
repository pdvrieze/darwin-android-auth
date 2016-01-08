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

import android.app.Service;
import android.content.Intent;
import android.os.IBinder;


/**
 * The service that makes the authenticator available.
 */
public class DarwinAuthenticatorService extends Service {

  private DarwinAuthenticator mAuthenticator;

  @Override
  public void onCreate() {
    super.onCreate();
    mAuthenticator = new DarwinAuthenticator(this);
  }

  @Override
  public IBinder onBind(final Intent arg0) {
    return mAuthenticator.getIBinder();
  }

}
