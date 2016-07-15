package com.mastek.security.pgp;

import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.NoSuchProviderException;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.util.encoders.Base64;

import com.mastek.security.pgp.util.CryptLib;


/**
 * @author mangesh13413
 *
 */
public class Android 
{
	public static void main(String[] args) {
	
		String originalMessage="{'name' : 'abccc','salary' : '100001'}";
		byte[] originalMessageByte=originalMessage.getBytes();
		FileInputStream publicKeyStream;
		String encryptionType="AES";
		try {
			publicKeyStream = new FileInputStream("D:\\tmp\\publickey.dat");
			
			byte[] encryptedBytes = CryptLib.pgpEncryptByte(originalMessageByte,encryptionType,CryptLib.readPublicKey(publicKeyStream), null,true, true);
			
			//writting encrypted bytes into file for now.
			FileOutputStream dfis = new FileOutputStream("D:\\tmp\\encryptedCipher.asc");
			
	        dfis.write(encryptedBytes);
	        dfis.close();
			
			String encryptedMessage=new String(encryptedBytes);
			
			System.out.println("Original Message::::"+"'"+originalMessage+"'");
			System.out.println("\n Encrypted Message: \n"+encryptedMessage);
			
		} catch (NoSuchProviderException | IOException | PGPException  e) {
			e.getMessage();
			e.printStackTrace();
		}
		

	}
}
