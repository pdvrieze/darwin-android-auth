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

/*
 * This software is provided 'as-is', without any express or implied
 * warranty.  In no event will Google be held liable for any damages
 * arising from the use of this software.
 *
 * Permission is granted to anyone to use this software for any purpose,
 * including commercial applications, and to alter it and redistribute it
 * freely, as long as the origin is not misrepresented.
 */

package uk.ac.bournemouth.darwin.auth;

import android.os.Build;
import android.os.Process;
import android.support.annotation.GuardedBy;
import android.util.Log;

import java.io.*;
import java.security.*;


/**
 * Fixes for the output of the default PRNG having low entropy.
 * <p/>
 * The fixes need to be applied via {@link #applyActually()} before any use of Java
 * Cryptography Architecture primitives. A good place to invoke them is in the
 * application's {@code onCreate}.
 */
@SuppressWarnings({"boxing", "serial", "resource"})
public final class PRNGFixes {

  @SuppressWarnings("unused")
  private static final class ApplyHelper {

    static {
      PRNGFixes.applyActually();
    }

    static void ensureApplied() { // Class loading will actually ensure a single application that is atomic.
      Log.d(PRNGFixes.class.getSimpleName(), "Ensuring PRNG fix has been applied when needed");
    }
  }

  /**
   * {@code Provider} of {@code SecureRandom} engines which pass through
   * all requests to the Linux PRNG.
   */
  @SuppressWarnings("CloneableClassWithoutClone")
  private static final class LinuxPRNGSecureRandomProvider extends Provider {

// Object Initialization
    LinuxPRNGSecureRandomProvider() {
      super("LinuxPRNG", 1.0, "A Linux-specific random number provider that uses" + " /dev/urandom");
      // Although /dev/urandom is not a SHA-1 PRNG, some apps
      // explicitly request a SHA1PRNG SecureRandom and we thus need to
      // prevent them from getting the default implementation whose output
      // may have low entropy.
      put("SecureRandom.SHA1PRNG", LinuxPRNGSecureRandom.class.getName());
      put("SecureRandom.SHA1PRNG ImplementedIn", "Software");
    }
// Object Initialization end
  }

  /**
   * {@link SecureRandomSpi} which passes all requests to the Linux PRNG
   * ({@code /dev/urandom}).
   */
  static class LinuxPRNGSecureRandom extends SecureRandomSpi {

        /*
         * IMPLEMENTATION NOTE: Requests to generate bytes and to mix in a seed
         * are passed through to the Linux PRNG (/dev/urandom). Instances of
         * this class seed themselves by mixing in the current time, PID, UID,
         * build fingerprint, and hardware serial number (where available) into
         * Linux PRNG.
         *
         * Concurrency: Read requests to the underlying Linux PRNG are
         * serialized (on _lock) to ensure that multiple threads do not get
         * duplicated PRNG output.
         */

    private static final File URANDOM_FILE = new File("/dev/urandom");

      @SuppressWarnings("FieldNamingConvention")
      private static final Object _lock = new Object();

    /**
     * Input stream for reading from Linux PRNG or {@code null} if not yet
     * opened.
     */
    @GuardedBy("_lock")
    private static DataInputStream _urandomIn;

    /**
     * Output stream for writing to Linux PRNG or {@code null} if not yet
     * opened.
     */
    @GuardedBy("_lock")
    private static OutputStream _urandomOut;

    /**
     * Whether this engine instance has been seeded. This is needed because
     * each instance needs to seed itself if the client does not explicitly
     * seed it.
     */
    private boolean isUnseeded = true;

    @Override
    protected void engineSetSeed(final byte[] seed) {
      try {
        final OutputStream out;
        synchronized (_lock) {
          out = getUrandomOutputStream();
        }
        out.write(seed);
        out.flush();
      } catch (IOException e) {
        // On a small fraction of devices /dev/urandom is not writable.
        // Log and ignore.
        Log.w(PRNGFixes.class.getSimpleName(), "Failed to mix seed into " + URANDOM_FILE);
      } finally {
          isUnseeded = false;
      }
    }

    @Override
    protected void engineNextBytes(final byte[] bytes) {
      if (isUnseeded) {
        // Mix in the device- and invocation-specific seed.
        engineSetSeed(generateSeed());
      }

      try {
        final DataInputStream in;
        synchronized (_lock) {
          in = getUrandomInputStream();
        }
        //noinspection SynchronizationOnLocalVariableOrMethodParameter
        synchronized (in) {
          in.readFully(bytes);
        }
      } catch (IOException e) {
        throw new SecurityException("Failed to read from " + URANDOM_FILE, e);
      }
    }

    @Override
    protected byte[] engineGenerateSeed(final int numBytes) {
      final byte[] seed = new byte[numBytes];
      engineNextBytes(seed);
      return seed;
    }

    private static DataInputStream getUrandomInputStream() {
      synchronized (_lock) {
        if (_urandomIn == null) {
          // NOTE: Consider inserting a BufferedInputStream between
          // DataInputStream and FileInputStream if you need higher
          // PRNG output performance and can live with future PRNG
          // output being pulled into this process prematurely.
          try {
            _urandomIn = new DataInputStream(new FileInputStream(URANDOM_FILE));
          } catch (IOException e) {
            throw new SecurityException("Failed to open " + URANDOM_FILE + " for reading", e);
          }
        }
        return _urandomIn;
      }
    }

    private static OutputStream getUrandomOutputStream() throws IOException {
      synchronized (_lock) {
        if (_urandomOut == null) {
          _urandomOut = new FileOutputStream(URANDOM_FILE);
        }
        return _urandomOut;
      }
    }
  }
  private static final int VERSION_CODE_JELLY_BEAN = 16;
  private static final int VERSION_CODE_JELLY_BEAN_MR2 = 18;
  private static final byte[] BUILD_FINGERPRINT_AND_DEVICE_SERIAL = getBuildFingerprintAndDeviceSerial();
    private static final int RANDOM_BYTES_TO_READ = 1024;

// Object Initialization
  /** Hidden constructor to prevent instantiation. */
  @SuppressWarnings("unused")
  private PRNGFixes() {}
// Object Initialization end

// Property accessors start
  private static byte[] getBuildFingerprintAndDeviceSerial() {
    final StringBuilder result = new StringBuilder();
    final String fingerprint = Build.FINGERPRINT;
    if (fingerprint != null) {
      result.append(fingerprint);
    }
    final String serial = getDeviceSerialNumber();
    if (serial != null) {
      result.append(serial);
    }
    try {
      return result.toString().getBytes("UTF-8");
    } catch (UnsupportedEncodingException e) {
      throw new RuntimeException("UTF-8 encoding not supported");
    }
  }

  /**
   * Gets the hardware serial number of this device.
   *
   * @return serial number or {@code null} if not available.
   */
  private static String getDeviceSerialNumber() {
    // We're using the Reflection API because Build.SERIAL is only available
    // since API Level 9 (Gingerbread, Android 2.3).
    try {
      return (String) Build.class.getField("SERIAL").get(null);
    } catch (Exception ignored) {
      return null;
    }
  }
// Property acccessors end

  /**
   * Method that can be called to ensure that the fix has been applied. This mainly triggers class loading.
   */
  public static void ensureApplied() {
    ApplyHelper.ensureApplied();
  }

  /**
   * Applies all fixes.
   *
   * @throws SecurityException if a fix is needed but could not be applied.
   */
  private static void applyActually() {
    applyOpenSSLFix();
    installLinuxPRNGSecureRandom();
  }

  /**
   * Applies the fix for OpenSSL PRNG having low entropy. Does nothing if the
   * fix is not needed. (any version < jellybean >=kitkat
   *
   * @throws SecurityException if the fix is needed but could not be applied.
   */
  private static void applyOpenSSLFix() throws SecurityException {
    if ((Build.VERSION.SDK_INT < VERSION_CODE_JELLY_BEAN) || (Build.VERSION.SDK_INT > VERSION_CODE_JELLY_BEAN_MR2)) {
      // No need to apply the fix
      return;
    }

    try {
      // Mix in the device- and invocation-specific seed.
      //noinspection PrimitiveArrayArgumentToVariableArgMethod
      Class.forName("org.apache.harmony.xnet.provider.jsse.NativeCrypto")
           .getMethod("RAND_seed", byte[].class)
           .invoke(null, generateSeed());

      // Mix output of Linux PRNG into OpenSSL's PRNG
      final int bytesRead = ((Integer) Class.forName("org.apache.harmony.xnet.provider.jsse.NativeCrypto")
                                            .getMethod("RAND_load_file", String.class, long.class)
                                            .invoke(null, "/dev/urandom", RANDOM_BYTES_TO_READ)).intValue();
      if (bytesRead != RANDOM_BYTES_TO_READ) {
        throw new IOException("Unexpected number of bytes read from Linux PRNG: " + bytesRead);
      }
    } catch (Exception e) {
      throw new SecurityException("Failed to seed OpenSSL PRNG", e);
    }
  }

  /**
   * Generates a device- and invocation-specific seed to be mixed into the
   * Linux PRNG.
   */
  private static byte[] generateSeed() {
    try {
      final ByteArrayOutputStream seedBuffer = new ByteArrayOutputStream();
      @SuppressWarnings("IOResourceOpenedButNotSafelyClosed")
      final DataOutputStream seedBufferOut = new DataOutputStream(seedBuffer);
      seedBufferOut.writeLong(System.currentTimeMillis());
      seedBufferOut.writeLong(System.nanoTime());
      seedBufferOut.writeInt(Process.myPid());
      seedBufferOut.writeInt(Process.myUid());
      seedBufferOut.write(BUILD_FINGERPRINT_AND_DEVICE_SERIAL);
      seedBufferOut.close();
      return seedBuffer.toByteArray();
    } catch (IOException e) {
      throw new SecurityException("Failed to generate seed", e);
    }
  }

  /**
   * Installs a Linux PRNG-backed {@code SecureRandom} implementation as the
   * default. Does nothing if the implementation is already the default or if
   * there is not need to install the implementation.
   *
   * @throws SecurityException if the fix is needed but could not be applied.
   */
  private static void installLinuxPRNGSecureRandom() throws SecurityException {
    if (Build.VERSION.SDK_INT > VERSION_CODE_JELLY_BEAN_MR2) {
      // No need to apply the fix
      return;
    }

    // Install a Linux PRNG-based SecureRandom implementation as the
    // default, if not yet installed.
    final Provider[] secureRandomProviders = Security.getProviders("SecureRandom.SHA1PRNG");
    if ((secureRandomProviders == null) || (secureRandomProviders.length < 1) || (!LinuxPRNGSecureRandomProvider.class.equals(secureRandomProviders[0]
                                                                                                                                      .getClass()))) {
      Security.insertProviderAt(new LinuxPRNGSecureRandomProvider(), 1);
    }

    // Assert that new SecureRandom() and
    // SecureRandom.getInstance("SHA1PRNG") return a SecureRandom backed
    // by the Linux PRNG-based SecureRandom implementation.
    final SecureRandom rng1 = new SecureRandom();
    if (!LinuxPRNGSecureRandomProvider.class.equals(rng1.getProvider().getClass())) {
      throw new SecurityException("new SecureRandom() backed by wrong Provider: " + rng1.getProvider().getClass());
    }

    final SecureRandom rng2;
    try {
      rng2 = SecureRandom.getInstance("SHA1PRNG");
    } catch (NoSuchAlgorithmException e) {
      throw new SecurityException("SHA1PRNG not available", e);
    }
    if (!LinuxPRNGSecureRandomProvider.class.equals(rng2.getProvider().getClass())) {
      throw new SecurityException("SecureRandom.getInstance(\"SHA1PRNG\") backed by wrong" + " Provider: " + rng2.getProvider()
                                                                                                                 .getClass());
    }
  }
}