package pl.mchaniewski.aes;

import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

import org.bouncycastle.util.encoders.Hex;

public class AesOne {
	public static final String PROVIDER = "BC";
	public static final int IV_LENGTH = 16;
	private static final String HASH_ALGORITHM = "SHA-512";
	private static final String PBE_ALGORITHM = "PBEWithSHA256And256BitAES-CBC-BC";
	private static final String CIPHER_ALGORITHM = "AES/CBC/PKCS5Padding";
	private static final String SECRET_KEY_ALGORITHM = "AES";

	public String decrypt(SecretKey secret, String encrypted)
			throws IllegalStateException, IllegalBlockSizeException,
			BadPaddingException, InvalidKeyException,
			InvalidAlgorithmParameterException, NoSuchAlgorithmException,
			NoSuchProviderException, NoSuchPaddingException,
			UnsupportedEncodingException {
		Cipher decryptionCipher = Cipher
				.getInstance(CIPHER_ALGORITHM, PROVIDER);
		String ivHex = encrypted.substring(0, IV_LENGTH * 2);
		String encryptedHex = encrypted.substring(IV_LENGTH * 2);
		IvParameterSpec ivspec = new IvParameterSpec(Hex.encode(ivHex
				.getBytes()));
		decryptionCipher.init(Cipher.DECRYPT_MODE, secret, ivspec);
		byte[] decryptedText = decryptionCipher.doFinal(Hex.encode(encryptedHex
				.getBytes()));
		String decrypted = new String(decryptedText, "UTF-8");
		return decrypted;
	}
}
