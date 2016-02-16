package org.apache.commons.compress.archivers.zip;

/**
 * Exception thrown when a password is known to be bad. Many
 * algorithms include small tests that quickly determine that a
 * password is definitely bad or probably good. The CRC checksum
 * or message digest of the decrypted content should still be
 * verified in addition to this test.
 * 
 * TODO: is there an existing exception that is a better choice
 * for this?
 * 
 * @author Bear Giles <bgiles@coyotesong.com>
 */
public class BadPasswordException extends Exception {
    private static final long serialVersionUID = 1L;
    
    public BadPasswordException() {
        
    }
}