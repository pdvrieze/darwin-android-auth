package uk.ac.bournemouth.darwin.auth;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;

import javax.net.ssl.HttpsURLConnection;


public class HttpResponseException extends IOException {

  private static final long serialVersionUID = -1709759910920830203L;

  private static final String RESPONSE_BASE = "Unexpected HTTP Response: ";

  public HttpResponseException(HttpsURLConnection pC) {
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
