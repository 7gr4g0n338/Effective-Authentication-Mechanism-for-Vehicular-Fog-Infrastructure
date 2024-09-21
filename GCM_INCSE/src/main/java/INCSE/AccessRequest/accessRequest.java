package INCSE.AccessRequest;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.sql.Connection;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Date;

import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.modes.CCMBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.json.JSONObject;

import INCSE.serverHttp.RestHttpClient;

import org.bouncycastle.crypto.digests.SHA256Digest;

public class accessRequest {
	// byte[] resources = null;
	public static final String Ks = "taokhoaks123456789";
	public static final int nonceSize = 12;

	private static String originator = "admin:admin";
	private static String cseProtocol = "http";
//	private static String cseIp = "10.8.77.7";
	private static String cseIp = "127.0.0.1";
	private static int csePort = 8081;
	private static String cseId = "in-cse";
	private static String cseName = "in-name";
	private static String aeName = "temperature";
	private static String cntData = "DATA";



	private static String csePoa = cseProtocol + "://" + cseIp + ":" + csePort;

	private static byte[] hexStringToByteArray(String s) {
		int len = s.length();
		byte[] data = new byte[len / 2];
		for (int i = 0; i < len; i += 2) {
			data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4) + Character.digit(s.charAt(i + 1), 16));
		}
		return data;
	}

	/* Convert long to byte array */
	private static byte[] longToByteArray(long value) {
		ByteBuffer buffer = ByteBuffer.allocate(Long.BYTES);
		buffer.putLong(value);
		return buffer.array();

	}

	/* Convert a string representation in its hexadecimal string */
	private static String toHex(String arg) {
		return String.format("%02x", new BigInteger(1, arg.getBytes()));
	}

	/* Transform a byte array in an hexadecimal string */
	private static String toHex(byte[] data) {
		StringBuilder sb = new StringBuilder();
		for (byte b : data) {
			sb.append(String.format("%02x", b & 0xff));
		}
		return sb.toString();
	}

	private static String convertHexToString(String hex) {

		StringBuilder sb = new StringBuilder();
		StringBuilder temp = new StringBuilder();

		// 49204c6f7665204a617661 split into two characters 49, 20, 4c...
		for (int i = 0; i < hex.length() - 1; i += 2) {

			// grab the hex in pairs
			String output = hex.substring(i, (i + 2));
			// convert hex to decimal
			int decimal = Integer.parseInt(output, 16);
			// convert the decimal to character
			sb.append((char) decimal);

			temp.append(decimal);
		}

		return sb.toString();
	}

	// concatByteArray:Chuyen String ve byte
	private static byte[] concatByteArrays(byte[] a, byte[] b) {
		ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
		try {
			outputStream.write(a);
			outputStream.write(b);
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		byte[] concatResult = outputStream.toByteArray();
		return concatResult;
	}

	/* Perform SHA256 and return the result */
	private static byte[] sha256(byte[] data) {
		SHA256Digest digest = new SHA256Digest();
		byte[] hash = new byte[digest.getDigestSize()];
		digest.update(data, 0, data.length);
		digest.doFinal(hash, 0);
		return hash;
	}

	public static String getUri() {
		return csePoa + "/~/" + cseId + "/" + cseName + "/" + aeName + "/" + cntData + "/la";
	}

	public static String getAcp(String permission) {
		String acp = null;
		System.out.println("permission getAcp: " + permission);
		String test1 = "32";
		String test2 = "34";
		if (permission.equalsIgnoreCase(test1)) {
			return acp = "guest:guest";

		} else if (permission.equalsIgnoreCase(test2)) {
			return acp = "admin:admin";
		} else {
			System.out.println("permission does not exist yet");
			return acp;
		}
	}

	public static String authenticationTicket(String Qu, String ticket, String n) {
		// Creat Kt=(Qu||Ks)
		DateFormat dateFormat = new SimpleDateFormat("yyyy/MM/dd HH:mm:ss:SSS");
		Date date1 = new Date();
		System.out.println("***************time start 7.2 BUGGG****************"+dateFormat.format(date1));
		long time7_2 = System.nanoTime();
		System.out.println("********************time start 7.2*****************" + time7_2);
		System.out.println("\n >>>>>>> Process 7.2 to 7.5 Kt, D_Kt(Ticket), Ts, retrieve AE_ID .....");
		System.out.println("\n >>>>>>> Process 7.2 created Kt = H(Qu||Ks) .....");
		byte[] IDprivRandConcat = concatByteArrays(hexStringToByteArray(Qu), hexStringToByteArray(Ks));
		long multi = System.nanoTime();
		byte[] Kt = sha256(IDprivRandConcat);
		System.out.println("******SHA256_7_2: " + (System.nanoTime() - multi));
		System.out.println("Kt :" + toHex(Kt));

		// Decrypt Ticket = Dkt(Ticket)--> TokenID, Rn,Texp
		System.out.println("\n >>>>>>> Process 7.3 Decrypt Ticket = Dkt(Ticket)--> TokenID, Rn,Texp .....");
		multi = System.nanoTime();
		String resources = AesGcm256.decrypt(ticket, Kt, AesGcm256.HexToByte(n));
		System.out.println("******AESGCM_7_3: " + (System.nanoTime() - multi));
		System.out.println("Decrypted Resource: " + resources);

		String appData = convertHexToString(resources);
		String[] data = appData.split("\\|\\|");

		String tokenID = data[0];
		String Rn = data[1];
		String Texp = data[2];
		String Permission = data[3];

		System.out.println("tokenID: " + tokenID);
		System.out.println("Resounce name Rn:  " + Rn);
		System.out.println("Expired Time Texp:  " + Texp);
		System.out.println("Permission:  " + Permission);

		/* Generate a timestamp Ts */
		System.out.println("\n >>>>>>> Process 7.4 created Ts.....");
		Date date = new Date();
		long regTimestamp = date.getTime();
		byte[] regTimestampBytes = longToByteArray(regTimestamp);

		// retrieve AE
		System.out.println("\n >>>>>>> Process 7.5 retrieve AE-ID.....");
		JSONObject getBody = new JSONObject(
				RestHttpClient.get(originator, csePoa + "/~/" + cseId + "/" + cseName + "/" + Rn).getBody());
		System.out.println("=================>AE-ID: " + getBody.getJSONObject("m2m:ae").getString("aei"));
		String AEID = getBody.getJSONObject("m2m:ae").getString("aei");
		System.out.println("***************time end 7.5***************" + System.nanoTime());
		DateFormat dateFormat2 = new SimpleDateFormat("yyyy/MM/dd HH:mm:ss:SSS");
		Date date2 = new Date();
		System.out.println("***************time end 7.5 BUGGG****************"+dateFormat.format(date2));
		System.out.println("***************time process 7.2 to 7.5***************" + (System.nanoTime()-time7_2));
		return AEID + "|" + tokenID + "|" + toHex(regTimestampBytes) + "|" + Permission;
	}

	public static String EncryptURL(String Sk, String Permission) {

		// Generate a nonce (12 bytes) to be used for AES_256_CCM_8
		DateFormat dateFormat = new SimpleDateFormat("yyyy/MM/dd HH:mm:ss:SSS");
		Date date = new Date();
		System.out.println("***************time start 7.7 BUGGG****************"+dateFormat.format(date));
		long time7_7 = System.nanoTime();
		System.out.println("***************time start 7.7***************" + time7_7);
		System.out.println("\n >>>>>>> Process 7.7 Encrypt EU=E_Sk(URL) .....");
		SecureRandom random = new SecureRandom();
		random = new SecureRandom();
		byte[] nonce3 = new byte[nonceSize];
		random.nextBytes(nonce3); // Fill the nonce with random bytes

		// Encrypt the URL
		System.out.println(">>>>>>>>>>>>>>>>>>>>>>>");
		System.out.println("sessionKey: " + Sk);

		String URL = getAcp(Permission) + "|" + getUri();
		long multi = System.nanoTime();
		String EU = AesGcm256.encrypt(URL, AesGcm256.HexToByte(Sk), nonce3);
		System.out.println("******AESGCM_7_7: " + (System.nanoTime() - multi));
		System.out.println("Encrypted URIr: " + EU);
		System.out.println("***************time end 7.7***************" + System.nanoTime());
		DateFormat dateFormat2 = new SimpleDateFormat("yyyy/MM/dd HH:mm:ss:SSS");
		Date date2 = new Date();
		System.out.println("***************time end 7.7 BUGGG****************"+dateFormat.format(date2));
		System.out.println("***************time process 7.7***************" + (System.nanoTime()-time7_7));

		return EU + "|" + toHex(nonce3);
	}
}
