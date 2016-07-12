package com.pgp;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.NoSuchProviderException;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPSecretKey;

import com.pgp.util.CryptLib;

public class TestCryptLib 
{
	public static void main(String[] args) {
		
		String originalMessage="{'name' : 'Mangesh','salary' : '10000','Number':'13413'}";
		byte[] originalMessageByte=originalMessage.getBytes();
		String encryptionType="AES";
		String password="benow123";
		FileInputStream publicKeyStream;
		try {
			publicKeyStream = new FileInputStream("D:\\tmp\\publickey.dat");
			FileInputStream secreyKeyFile = new FileInputStream("D:\\tmp\\privatekey.dat");
			
			String encryptedString;
			try {
				encryptedString = CryptLib.PGPEncryptString(originalMessage,encryptionType,CryptLib.readPublicKey(publicKeyStream), null,true, true);
				String decryptedMessage;
				System.out.println("Original Message::::"+"'"+originalMessage+"'");
				System.out.println("\n Encrypted Message: \n"+encryptedString);
				byte[] encryptedBytes=encryptedString.getBytes();
				decryptedMessage = CryptLib.pgpDecryptString(encryptedString, secreyKeyFile, password);
				
				System.out.println("decrypted Message:"+decryptedMessage);
			} catch (NoSuchProviderException e1) {
				// TODO Auto-generated catch block
				e1.printStackTrace();
			}
						
		} catch (IOException | PGPException  e) {
			e.getMessage();
			e.printStackTrace();
		}
		

	}

}
