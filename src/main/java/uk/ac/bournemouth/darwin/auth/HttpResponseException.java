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

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;


public class HttpResponseException extends IOException {

  private static final long serialVersionUID = -1709759910920830203L;

  private static final String RESPONSE_BASE = "Unexpected HTTP Response: ";

  public HttpResponseException(HttpURLConnection pC) {
    super(getMessage(pC));
  }

  private static String getMessage(HttpURLConnection pC) {
    StringBuilder result = new StringBuilder();
    try {
      result.append(RESPONSE_BASE)
            .append(pC.getResponseCode())
            .append(' ').append(pC.getResponseMessage())
            .append("\n\n");

      BufferedReader in = new BufferedReader(new InputStreamReader(pC.getErrorStream(), Util.UTF8));
      for(String line = in.readLine(); line!=null; line=in.readLine()) {
        // TODO normalize a bit if possible
        result.append(line).append('\n');
      }

    } catch (IOException e) {
      if (result.length()<=RESPONSE_BASE.length()) {
        return RESPONSE_BASE + "No details possible";
      } else {
        String s = result.toString();
        if (s.startsWith(RESPONSE_BASE)) {
          result.delete(RESPONSE_BASE.length(), result.length());
          result.append("Partial details only: ")
                .append(s.substring(RESPONSE_BASE.length()));
        } else {
          result = new StringBuilder();
          result.append(RESPONSE_BASE+"Partial details only: ")
                .append(s);
        }
      }
    }

    return result.toString();
  }

}
