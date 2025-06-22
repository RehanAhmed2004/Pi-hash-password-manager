import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;

public class AesCrypt {

    // Use first 16 bytes of the key string
    private static SecretKeySpec getKey(String keyStr) {
        byte[] key = new byte[16];
        byte[] inputBytes = keyStr.getBytes();
        System.arraycopy(inputBytes, 0, key, 0, Math.min(inputBytes.length, key.length));
        return new SecretKeySpec(key, "AES");
    }

    public String encrypt(String plainText, String key) {
        System.out.println("Encrypting with key: " + key);
        try {
            SecretKeySpec secretKey = getKey(key);
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);
            byte[] encrypted = cipher.doFinal(plainText.getBytes());
            return Base64.getEncoder().encodeToString(encrypted);
        } catch (Exception e) {
            
            System.err.println("Encryption failed: " + e.getMessage());
            return "gend";
        }

    }

    public static String decrypt(String encryptedText, String key) {
        try {
            SecretKeySpec secretKey = getKey(key);
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.DECRYPT_MODE, secretKey);
            byte[] decrypted = cipher.doFinal(Base64.getDecoder().decode(encryptedText));
            return new String(decrypted);
        } catch (Exception e) {
            return null;
        }
    }
}
