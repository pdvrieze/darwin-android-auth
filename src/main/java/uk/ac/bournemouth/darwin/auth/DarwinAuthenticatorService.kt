/*
 * Copyright (c) 2018.
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
 * You should have received a copy of the GNU Lesser General Public License along with ProcessManager.  If not,
 * see <http://www.gnu.org/licenses/>.
 */

package uk.ac.bournemouth.darwin.auth

import android.app.Service
import android.content.Intent
import android.os.IBinder


/**
 * The service that makes the authenticator available.
 */
class DarwinAuthenticatorService : Service() {

    private lateinit var authenticator: DarwinAuthenticator

    override fun onCreate() {
        super.onCreate()
        authenticator = DarwinAuthenticator(this)
    }

    override fun onBind(intent: Intent): IBinder? {
        return authenticator.iBinder
    }

}
