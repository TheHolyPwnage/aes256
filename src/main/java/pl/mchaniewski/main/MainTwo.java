package pl.mchaniewski.main;

import java.security.MessageDigest;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.engines.RijndaelEngine;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.paddings.BlockCipherPadding;
import org.bouncycastle.crypto.paddings.PKCS7Padding;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Hex;

//echo "ala" | openssl enc -e -k "test" -base64 -aes-256-cbc -md sha256 -nosalt -iv 0 | openssl enc -d -k "test" -base64 -aes-256-cbc -md sha256 -nosalt -iv 0


public class MainTwo {

	/**
	 * @param args
	 */
	public static void main(String[] args) throws Exception {
		// String key =
		// "9F86D081884C7D659A2FEAA0C55AD015A3BF4F1B2B0B822CD15D6C15B0F00A08";
		String iv = "00000000000000000000000000000000";
		// String msg = "Q3B91c68MHmTXZ/eMmnmuQ==";

		// Bez -iv 0
		String key = "9F86D081884C7D659A2FEAA0C55AD015A3BF4F1B2B0B822CD15D6C15B0F00A08";
//		String msg = "B3YArzTcDeLsQXgXiBLBsw==";
		String msg = "gBLoBdf0YZm7h5XmF8fA4w==";

		// KeyParameter keyParam = new KeyParameter(Hex.decode(key.getBytes()));
		// CipherParameters params = new ParametersWithIV(keyParam, ivData);
		//
		// BlockCipherPadding padding = new PKCS7Padding();

		// Cipher ecipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
		// SecretKeySpec keySpec = new SecretKeySpec(Hex.decode(key), "AES");
		// ecipher.init(Cipher.DECRYPT_MODE, keySpec);
		// byte[] enc = ecipher.doFinal(Base64.decode(msg.getBytes()));

		// System.out.println(enc);
		// System.out.println(new String(enc));
		// System.out.println(Base64.encode(enc));
		// System.out.println(new String(Base64.encode(enc)));

		// CipherParameters cipherParameters = new
		// KeyParameter(Hex.decode(key));

		MessageDigest md = MessageDigest.getInstance("SHA-256");
		CipherParameters keyParameters = new KeyParameter(md.digest("test"
				.getBytes()));
		System.out.println(new String(Hex.encode(((KeyParameter) keyParameters)
				.getKey())));
		CipherParameters cipherParameters = new ParametersWithIV(keyParameters,
				Hex.decode(iv));

		BlockCipher aesBlock = new AESEngine();
//		BlockCipher aesBlock = new RijndaelEngine(256);
		BlockCipher blockCipher = new CBCBlockCipher(aesBlock);
		BlockCipherPadding blockCipherPadding = new PKCS7Padding();
		BufferedBlockCipher bufferedBlockCipher = new PaddedBufferedBlockCipher(
				blockCipher, blockCipherPadding);

//		 byte[] out = process(Base64.decode(msg), bufferedBlockCipher,
//		 cipherParameters, false);

		byte[] out = process("ala".getBytes(), bufferedBlockCipher,
				cipherParameters, true);

		System.out.println(out);
		System.out.println(new String(out));
		System.out.println(new String(Base64.encode(out)));
	}

	public static byte[] process(byte[] input,
			BufferedBlockCipher bufferedBlockCipher,
			CipherParameters cipherParameters, boolean forEncryption)
			throws InvalidCipherTextException {
		bufferedBlockCipher.init(forEncryption, cipherParameters);

		int inputOffset = 0;
		int inputLength = input.length;

		int maximumOutputLength = bufferedBlockCipher
				.getOutputSize(inputLength);
		byte[] output = new byte[maximumOutputLength];
		int outputOffset = 0;
		int outputLength = 0;

		int bytesProcessed;

		bytesProcessed = bufferedBlockCipher.processBytes(input, inputOffset,
				inputLength, output, outputOffset);
		outputOffset += bytesProcessed;
		outputLength += bytesProcessed;

		bytesProcessed = bufferedBlockCipher.doFinal(output, outputOffset);
		outputOffset += bytesProcessed;
		outputLength += bytesProcessed;

		if (outputLength == output.length) {
			return output;
		} else {
			byte[] truncatedOutput = new byte[outputLength];
			System.arraycopy(output, 0, truncatedOutput, 0, outputLength);
			return truncatedOutput;
		}
	}

}
