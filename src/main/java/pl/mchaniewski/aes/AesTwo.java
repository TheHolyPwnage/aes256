package pl.mchaniewski.aes;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.paddings.BlockCipherPadding;
import org.bouncycastle.crypto.paddings.PKCS7Padding;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.util.encoders.Hex;

public class AesTwo {

	private static final char[] HEX_CHARS = "0123456789abcdef".toCharArray();

	public static String asHex(byte[] buf) {
		char[] chars = new char[2 * buf.length];
		for (int i = 0; i < buf.length; ++i) {
			chars[2 * i] = HEX_CHARS[(buf[i] & 0xF0) >>> 4];
			chars[2 * i + 1] = HEX_CHARS[buf[i] & 0x0F];
		}
		return new String(chars);
	}

	public static byte[] toByte(String input) {
		return asHex(input.getBytes()).getBytes();
	}

	public static String dec(String password, String salt, String encString)
			throws Exception {

		byte[] ivData = Hex.encode(encString.substring(0, 32).getBytes());
		byte[] encData = Hex.encode(encString.substring(32).getBytes());

		// get raw key from password and salt
		PBEKeySpec pbeKeySpec = new PBEKeySpec(password.toCharArray(),
				toByte(salt), 50, 256);
		SecretKeyFactory keyFactory = SecretKeyFactory
				.getInstance("PBEWithSHA256And256BitAES-CBC-BC");
		SecretKeySpec secretKey = new SecretKeySpec(keyFactory.generateSecret(
				pbeKeySpec).getEncoded(), "AES");
		byte[] key = secretKey.getEncoded();

		// setup cipher parameters with key and IV
		KeyParameter keyParam = new KeyParameter(key);
		CipherParameters params = new ParametersWithIV(keyParam, ivData);

		// setup AES cipher in CBC mode with PKCS7 padding
		BlockCipherPadding padding = new PKCS7Padding();
		BufferedBlockCipher cipher = new PaddedBufferedBlockCipher(
				new CBCBlockCipher(new AESEngine()), padding);
		cipher.reset();
		cipher.init(false, params);

		// create a temporary buffer to decode into (it'll include padding)
		byte[] buf = new byte[cipher.getOutputSize(encData.length)];
		int len = cipher.processBytes(encData, 0, encData.length, buf, 0);
		len += cipher.doFinal(buf, len);

		// remove padding
		byte[] out = new byte[len];
		System.arraycopy(buf, 0, out, 0, len);

		// return string representation of decoded bytes
		return new String(out, "UTF-8");
	}

}
