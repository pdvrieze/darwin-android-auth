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

import java.io.IOException
import java.io.InputStreamReader
import java.net.HttpURLConnection


/**
 * An exception thrown when a http response is thrown that was unexpected. This class will actually attempt to get the
 * http response body as part of the message.
 * @constructor Create a new exception. Read the status from the given connection.
 * @param connection The connection that caused the exception.
 */
class HttpResponseException(connection: HttpURLConnection) : IOException(getMessage(connection)) {
    companion object {

        private const val serialVersionUID = -1709759910920830203L

        private val RESPONSE_BASE = "Unexpected HTTP Response:"

        private fun getMessage(connection: HttpURLConnection) = buildString {
            try {
                append(RESPONSE_BASE)
                append(connection.responseCode)
                append(' ').append(connection.responseMessage)
                append("\n\n")


                InputStreamReader(connection.errorStream, UTF8).useLines { line ->
                    append(line).append('\n')
                }

            } catch (e: IOException) {
                if (length <= RESPONSE_BASE.length) {
                    return "${RESPONSE_BASE} No details possible"
                } else {
                    val s = toString()
                    if (s.startsWith(RESPONSE_BASE)) {
                        setLength(RESPONSE_BASE.length)
                        append("Partial details only: ")
                            .append(s.substring(RESPONSE_BASE.length))
                    } else {
                        setLength(0)
                        append("${RESPONSE_BASE} Partial details only: ")
                            .append(s)
                    }
                }
            }
        }
    }

}
