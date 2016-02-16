package org.apache.commons.compress.archivers.zip;

import org.junit.Test;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PrintStream;
import java.util.zip.GZIPOutputStream;

public class TraditionalZipEncryptionTest {
    private static final char[] PASSWORD = "password".toCharArray();

    /**
     * Test encryption using the low-level method.
     */
    @Test
    public void testDirectEncryption() {
        final byte[] expected = new byte[256];
        for (int i = 0; i < expected.length; i++) {
            expected[i] = (byte) i;
        }

        final byte[] ciphertext = ZipUtil.copy(expected);
        final TraditionalZipEncryption.PRNG prng1 = new TraditionalZipEncryption.PRNG(PASSWORD);
        prng1.encryptBuffer(ciphertext, ciphertext.length);

        final byte[] actual = ZipUtil.copy(ciphertext);
        final TraditionalZipEncryption.PRNG prng2 = new TraditionalZipEncryption.PRNG(PASSWORD);
        prng2.decryptBuffer(actual, actual.length);

        assertArrayEquals(expected, actual);
    }

    /**
     * Test encryption using streams.
     */
    @Test
    public void testStreamEncryption() throws IOException, BadPasswordException {
        final byte[] expected = new byte[256];
        for (int i = 0; i < expected.length; i++) {
            expected[i] = (byte) i;
        }
        final int crc = 1;

        final ByteArrayOutputStream os0 = new ByteArrayOutputStream();
        final OutputStream os1 = new TraditionalZipEncryption.TraditionalZipEncryptionOutputStream(os0, PASSWORD, crc);
        os1.write(expected);
        os1.flush();
        final byte[] ciphertext = os0.toByteArray();
        os1.close();
        assertEquals(expected.length + 12, ciphertext.length);

        // dump(System.out, ciphertext);

        final ByteArrayInputStream is0 = new ByteArrayInputStream(ciphertext);
        final InputStream is1 = new TraditionalZipEncryption.TraditionalZipEncryptionInputStream(is0, PASSWORD, crc);

        final byte[] actual = new byte[expected.length];
        assertEquals(expected.length, is1.read(actual));
        is1.close();

        // dump(System.out, actual);

        assertArrayEquals(expected, actual);
    }

    /**
     * Test encryption using streams.
     */
    @Test(expected = BadPasswordException.class)
    public void testStreamEncryptionBadPassword() throws IOException, BadPasswordException {
        final byte[] expected = new byte[256];
        for (int i = 0; i < expected.length; i++) {
            expected[i] = (byte) i;
        }
        final int crc = 1;

        final ByteArrayOutputStream os0 = new ByteArrayOutputStream();
        final OutputStream os1 = new TraditionalZipEncryption.TraditionalZipEncryptionOutputStream(os0, PASSWORD, crc);
        os1.write(expected);
        os1.flush();
        final byte[] ciphertext = os0.toByteArray();
        os1.close();
        assertEquals(expected.length + 12, ciphertext.length);

        // dump(System.out, ciphertext);

        final ByteArrayInputStream is0 = new ByteArrayInputStream(ciphertext);
        final InputStream is1 = new TraditionalZipEncryption.TraditionalZipEncryptionInputStream(is0, "Password".toCharArray(), crc);

        final byte[] actual = new byte[expected.length];
        assertEquals(expected.length, is1.read(actual));
        is1.close();

        // dump(System.out, actual);

        assertArrayEquals(expected, actual);
    }

    /**
     * This is a simple demonstration that a bit of easily guessed
     * plaintext (e.g., the first few characters of an html file)
     * provides more than enough known plaintext data to crack the PRNG.
     */
    // @Test
    public void demonstrateCompressedTextWeakness() throws IOException {
        final byte[] expected1 = new byte[] { 0x1F, (byte) 0x8B, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                (byte) 0xB3, (byte) 0xC9, 0x28, (byte) 0xC9, (byte) 0xCD, 0x01, 0x00, 0x63,
                (byte) 0x85, (byte) 0xCE, (byte) 0x9B, 0x05, 0x00, 0x00, 0x00 };

        final ByteArrayOutputStream baos1 = new ByteArrayOutputStream();
        final GZIPOutputStream os1 = new GZIPOutputStream(baos1);
        os1.write("<html".getBytes());
        os1.flush();
        os1.close();
        assertArrayEquals(expected1, baos1.toByteArray());

        final byte[] expected2 = new byte[] { 0x1F, (byte) 0x8B, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                (byte) 0xB3, (byte) 0xCF1, 0x08, (byte) 0xF1, (byte) 0xF5, 0x01, 0x00, (byte) 0xD7,
                0x68, 0x5B, (byte) 0xAD, 0x05, 0x00, 0x00, 0x00 };

        final ByteArrayOutputStream baos2 = new ByteArrayOutputStream();
        final GZIPOutputStream os2 = new GZIPOutputStream(baos2);
        os2.write("<HTML".getBytes());
        os2.flush();
        os2.close();
        assertArrayEquals(expected2, baos2.toByteArray());
    }

    /**
     * Convenience method to print contents of buffer.
     * 
     * @param os
     * @param b
     * @throws IOException
     */
    public static void dump(PrintStream os, byte[] b) throws IOException {
        char[] x = "0123456789ABCDEF".toCharArray();
        for (int i = 0; i < b.length; i += 16) {
            os.printf("%06x  ", i);
            for (int j = 0; j < 16; j++) {
                if (j == 8) {
                    System.out.print("- ");
                }
                if (i + j < b.length) {
                    os.print(x[(b[i + j] >> 4) & 0xF]);
                    os.print(x[b[i + j] & 0xF]);
                } else {
                    os.print("  ");
                }
                os.print(" ");
            }
            os.print("  ");
            for (int j = 0; j < 16 && i + j < b.length; j++) {
                if (Character.isDefined(b[i + j]) && !Character.isISOControl(b[i + j])) {
                    os.print((char) b[i + j]);
                } else {
                    os.print(".");
                }
            }
            os.println();
        }
    }
}
