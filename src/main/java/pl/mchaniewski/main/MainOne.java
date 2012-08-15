package pl.mchaniewski.main;

import java.security.MessageDigest;

import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Hex;

import pl.mchaniewski.aes.AesTwo;

public class MainOne {

	/**
	 * @param args
	 */

	// echo "ala" | openssl enc -e -nosalt -k "test" -base64 -aes-256-cbc -p -md
	// sha256

	public static void main(String[] args) {
		String msg = "ala";
		String key = "test";
		String iv = "0";
		String salt = "";

		try {
			String encryptedMsg = AesTwo.dec(key, salt, new String(Base64
					.decode("U2FsdGVkX1+slFMm8C6nko9RybA8e+TkxmszYEL/HL4=")));

			MessageDigest md = MessageDigest.getInstance("SHA-256");
			byte[] encryptedMsgBytes = md.digest(key.getBytes("UTF-8"));

			System.out.println("Encrypted msg:"
					+ new String(Hex.encode(key.getBytes("UTF-8"))));
			System.out
					.println("Encrypted msg:" + new String(encryptedMsgBytes));
			System.out.println("Encrypted msg:"
					+ new String(Hex.encode(encryptedMsgBytes)));
			System.out.println("\n---------\nEncrypted msg:" + encryptedMsg);
			System.out.println("Encrypted msg:" + Hex.decode(encryptedMsg));
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

}
