package com.mastek.security.pgp;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;

import org.bouncycastle.openpgp.PGPException;

import com.mastek.security.pgp.util.CryptLib;

/**
 * @author mangesh13413
 *
 */
public class Server 
{
	
	public static void main(String[] args) 
	{
		Server server=new Server();
		String pubkeyStr=server.initPGP();
		System.out.println(pubkeyStr);
	}


	public String initPGP() // To be executed once for a deployment
	{
		String privateKeyFile="D:\\tmp\\privatekey.dat";
		String publicKeyFile="D:\\tmp\\publickey.dat";
		String id="BeNOW";
		String password="benow123";
		boolean isArmored = true;
		String pubkeyStr;
		try 
		{
			pubkeyStr = CryptLib.genKeyPair(publicKeyFile,privateKeyFile,id,password,isArmored);
			return pubkeyStr;
		} catch (InvalidKeyException | NoSuchProviderException | SignatureException | NoSuchAlgorithmException
				| IOException | PGPException e) 
		{
			e.getMessage();
			e.printStackTrace();
		} 
		return null;
				
		
		
	}

}
