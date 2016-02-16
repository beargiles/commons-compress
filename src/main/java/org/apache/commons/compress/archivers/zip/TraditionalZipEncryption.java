package org.apache.commons.compress.archivers.zip;

import java.io.FilterInputStream;
import java.io.FilterOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.SecureRandom;
import java.util.Random;

/**
 * Traditional ZIP encryption. This is a weak algorithm and should only be used
 * when required for legacy applications or when there is absolutely no
 * alternative but there is a legal requirement to "do something".
 * 
 * Cryptanalysis
 * 
 * This is a stream cipher that uses a PRNG based on the original key, a random
 * salt, and the plaintext stream. This sounds promising but internal state of
 * the PRNG is entirely determined if you know 12(?) consecutive values,
 * something easily within reach with the typical contents of zip files even if
 * they're compressed since modern documents have standard headers.
 *
 * The problem is that k0 depends solely on the existing value of k0 and the
 * current plaintext byte, k1 depends solely on the existing value of k1 and a
 * single byte from k0, k2 depends solely on the existing value of k2 and a
 * single byte from k1, and the PRNG depends solely on the value of k2. This
 * changes a 12-byte nonlinear feedback shift register to three 4-byte nonlinear
 * feedback shift registers. This is a far more tractable problem and even in
 * the early 2000s a desktop computer could crack the encryption in less than a
 * second.
 */
public class TraditionalZipEncryption {

    /**
     * InputStream that performs encryption consistent with the traditional ZIP
     * file encryption. This implementation is compatible with ZIP version 2.0
     * and higher.
     * 
     * @author bgiles
     */
    public static class TraditionalZipEncryptionInputStream extends FilterInputStream {
        private final PRNG prng;

        public TraditionalZipEncryptionInputStream(InputStream is, char[] password, int crc)
                throws BadPasswordException, IOException {
            super(is);

            // read encryption header
            final byte[] buffer = new byte[12];
            if (super.read(buffer, 0, buffer.length) != 12) {
                throw new IllegalStateException("Incomplete encryption header");
            }

            // initialize key.
            prng = new PRNG(password);
            prng.decryptBuffer(buffer, buffer.length);

            // verify checksum.
            if (buffer[11] != (byte) (crc & 0xFF)) {
                throw new BadPasswordException();
            }
        }

        @Override
        public int read(byte[] b, int off, int len) throws IOException {
            if (off < 0) {
                throw new IllegalArgumentException("offset cannot be negative");
            }
            if (len < 0) {
                throw new IllegalArgumentException("length cannot be negative");
            }

            // update encryption key
            if (off > 0) {
                skip(off);
            }

            // read and decrypt buffer
            final int r = super.read(b, 0, len);
            if (r > 0) {
                prng.decryptBuffer(b, r);
            }

            return r;
        }

        /**
         * Skip 'n' bytes. We must actually read the data in order to update the
         * encryption key.
         */
        @Override
        public long skip(long n) throws IOException {
            final byte[] buffer = new byte[1024];
            long off = 0;
            while (off < n) {
                int r = read(buffer, 0, (int) Math.min(n - off, buffer.length));
                if (r <= 0) {
                    break;
                }
                off += r;
            }
            return off;
        }

        /**
         * Clear key.
         */
        @Override
        public void close() throws IOException {
            prng.reset();
            super.close();
        }
    }

    /**
     * OutputStream that performs encryption consistent with the traditional ZIP
     * file encryption. This implementation is compatible with ZIP version 2.0
     * and higher.
     * 
     * @author bgiles
     */
    public static class TraditionalZipEncryptionOutputStream extends FilterOutputStream {
        private static final Random RANDOM = new SecureRandom();
        private final PRNG prng;

        public TraditionalZipEncryptionOutputStream(OutputStream os, char[] password, int crc) throws IOException {
            super(os);

            // create encryption header
            final byte[] buffer = new byte[12];
            RANDOM.nextBytes(buffer);
            buffer[11] = (byte) (crc % 0xFF);

            // initialize key and write encryption header.
            prng = new PRNG(password);
            prng.encryptBuffer(buffer, buffer.length);
            super.write(buffer, 0, buffer.length);
        }

        /**
         * Write buffer. Note: we make a copy of the original buffer instead of
         * encrypting it in place.
         */
        @Override
        public void write(byte[] b, int off, int len) throws IOException {
            final byte[] buffer = new byte[len];
            System.arraycopy(b, off, buffer, 0, len);
            prng.encryptBuffer(buffer, len);
            super.write(buffer, 0, len);
        }

        /**
         * Clear key.
         */
        @Override
        public void close() throws IOException {
            prng.reset();
            super.close();
        }
    }

    /**
     * PRNG used by traditional zip encryption.
     * 
     * Note: the encryption/decryption pair will work with <b>any</b> current()
     * method and success should not be used as proof that the class is
     * performing correct ZIP encryption. It <b>must</b> be compared to an
     * existing encrypted ZIP file.
     * 
     * @author bgiles
     */
    static final class PRNG {
        private static final int[] SALT = { 305419896, 591751049, 878082192 };
        private static final long[] crcTable = new long[256];
        private final int[] k = new int[] { SALT[0], SALT[1], SALT[2] };

        /**
         * Create table for fast CRC32 lookup.
         * {@see https://www.w3.org/TR/PNG-CRCAppendix.html}
         */
        static {
            for (int i = 0; i < crcTable.length; i++) {
                long c = i;
                for (int k = 0; k < 8; k++) {
                    c = (c >> 1) ^ ((c & 1) == 1 ? 0xedb88320L : 0);
                }
                crcTable[i] = c;
            }
        }
        
        /**
         * Initialize the key.
         * 
         * @param password
         */
        public PRNG(char[] password) {
            for (char ch : password) {
                update((byte) (ch & 0xFF));
            }
        }

        /**
         * Calculate the next CRC32 value.
         * 
         * @param last
         * @param ch
         * @return
         */
        int crc32(int last, int ch) {
            long r = crcTable[(last ^ ch) & 0xFF] ^ (last >> 8);
            return (int) (r & 0xFFFFFFFF);
        }

        /**
         * Update the internal key.
         * 
         * @param ch
         */
        void update(byte b) {
            // NLFSR 1
            k[0] = crc32(k[0], b);

            // NLFSR 2
            k[1] = k[1] + (k[0] & 0xFF);
            k[1] = k[1] * 134775813 + 1;

            // NLFSR 3
            k[2] = crc32(k[2], (k[1] >> 24) & 0xFF);
        }

        /**
         * Get the current PRNG value.
         * 
         * @return
         */
        byte current() {
            final int tmp = k[2] | 2;
            return (byte) ((tmp * (tmp ^ 1)) >> 8);
        }

        /**
         * Reset internal key.
         */
        void reset() {
            k[0] = SALT[0];
            k[1] = SALT[1];
            k[2] = SALT[2];
        }

        /**
         * Encrypt a single byte
         * @param b
         * @return
         */
        public byte encrypt(byte b) {
            byte t = (byte) (b ^ this.current());
            this.update(b);
            return t;
        }
        
        /**
         * Decrypt a single byte
         * @param b
         * @return
         */
        public byte decrypt(byte b) {
            byte t = (byte) (b ^ this.current());
            this.update(t);
            return t;
        }

        /**
         * Encrypt a buffer.
         * 
         * @param b
         * @param len
         */
        public void encryptBuffer(byte[] b, int len) {
            for (int i = 0; i < b.length && i < len; i++) {
                b[i] = encrypt(b[i]);
            }
        }

        /**
         * Decrypt a buffer.
         * 
         * @param b
         * @param len
         */
        public void decryptBuffer(byte[] b, int len) {
            for (int i = 0; i < b.length && i < len; i++) {
                b[i] = decrypt(b[i]);
            }
        }
    }
}
