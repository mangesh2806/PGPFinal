package com.mastek.security.pgp.util;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.SignatureException;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Date;
import java.util.Iterator;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.io.IOUtils;
import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.bcpg.RSASecretBCPGKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPCompressedData;
import org.bouncycastle.openpgp.PGPCompressedDataGenerator;
import org.bouncycastle.openpgp.PGPEncryptedData;
import org.bouncycastle.openpgp.PGPEncryptedDataGenerator;
import org.bouncycastle.openpgp.PGPEncryptedDataList;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPKeyPair;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPLiteralDataGenerator;
import org.bouncycastle.openpgp.PGPObjectFactory;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyEncryptedData;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.operator.PGPDigestCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPDigestCalculatorProviderBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPKeyConverter;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyEncryptorBuilder;

import android.util.Base64;

/**
 * @author mangesh13413
 *
 */
public class CryptLib {

    public byte[] SHA256(String paramString)throws Exception{
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        md.update(paramString.getBytes("UTF-8"));
        byte[] digest = md.digest();
        return digest;
    }

    public byte[] encrypt(byte[] data, byte[] key)throws Exception
    {
        SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
        byte[] iv = new byte[16];
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        Cipher acipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        byte[] arrayOfByte1;
        acipher.init(Cipher.ENCRYPT_MODE, keySpec,ivSpec);
        arrayOfByte1 = acipher.doFinal(data);
        return arrayOfByte1;
    }

    public byte[] decrypt(byte[] data, byte[] key)throws Exception
    {
        SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
        byte[] iv = new byte[16];
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        Cipher acipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        byte[] arrayOfByte1;
        acipher.init(Cipher.DECRYPT_MODE, keySpec,ivSpec);
        arrayOfByte1 = acipher.doFinal(data);
        return arrayOfByte1;
    }


    public PrivateKey readPrivateKeyFromString(String privateKeyData) throws InvalidKeySpecException,
            NoSuchAlgorithmException, IOException {

        byte[] keyBytes = Base64.decode(privateKeyData, Base64.NO_WRAP);

        // Get private Key
        PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory fact = KeyFactory.getInstance("RSA");
        PrivateKey privateKey = fact.generatePrivate(pkcs8EncodedKeySpec);

        return privateKey;
    }

    public String decryptData(String encryptedData, PrivateKey privateKey){

        try {
             byte[] encryptedDataBytes = Base64.decode(encryptedData, Base64.NO_WRAP);

            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
            byte[] decryptedData = cipher.doFinal(encryptedDataBytes);
            String palinTextDecryptedData = new String(decryptedData);

            return palinTextDecryptedData;
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    public byte[] hexStringToByteArray(String s) {
        byte[] b = new byte[s.length() / 2];
        for (int i = 0; i < b.length; i++) {
            int index = i * 2;
            int v = Integer.parseInt(s.substring(index, index + 2), 16);
            b[i] = (byte) v;
        }
        return b;
    }
    
    
    //PGP methods starts from here
    /**
     * Simple PGP encryptor between byte[].
     * 
     * @param clearData
     *            The test to be encrypted
     * @param public key
     *            The pass phrase (key). This method assumes that the key is a
     *            simple pass phrase, and does not yet support RSA or more
     *            sophisiticated keying.
     * @param encryptionType
     * 			  encryption type takes input as AES or blank           
     * @param fileName
     *            File name. This is used in the Literal Data Packet (tag 11)
     *            which is really inly important if the data is to be related to
     *            a file to be recovered later. Because this routine does not
     *            know the source of the information, the caller can set
     *            something here for file name use that will be carried. If this
     *            routine is being used to encrypt SOAP MIME bodies, for
     *            example, use the file name from the MIME type, if applicable.
     *            Or anything else appropriate.
     * 
     * @param armor
     * 
     * @return encrypted data in bytes.
     * @exception IOException
     * @exception PGPException
     * @exception NoSuchProviderException
     */
    public static byte[] pgpEncryptByte(byte[] clearData,String encryptionType,PGPPublicKey publicKey,
            String fileName,boolean withIntegrityCheck, boolean armor)
            throws IOException, PGPException, NoSuchProviderException {
    	Security.addProvider(new BouncyCastleProvider());
		
        if (fileName == null) {
            fileName = PGPLiteralData.CONSOLE;
        }
       
        ByteArrayOutputStream encOut = new ByteArrayOutputStream();

        OutputStream out = encOut;
        if (armor) {
            out = new ArmoredOutputStream(out);
        }

        ByteArrayOutputStream bOut = new ByteArrayOutputStream();

        PGPCompressedDataGenerator comData = new PGPCompressedDataGenerator(
                PGPCompressedDataGenerator.ZIP);
        OutputStream cos = comData.open(bOut); // open it with the final
        // destination
        PGPLiteralDataGenerator lData = new PGPLiteralDataGenerator();

        // we want to generate compressed data. This might be a user option
        // later,
        // in which case we would pass in bOut.
        OutputStream pOut = lData.open(cos, // the compressed output stream
                PGPLiteralData.BINARY, fileName, // "filename" to store
                clearData.length, // length of clear data
                new Date() // current time
                );
        
      
        pOut.write(clearData);

        lData.close();
        comData.close();
        if(encryptionType.equals("AES"))
        {
        PGPEncryptedDataGenerator cPk = new PGPEncryptedDataGenerator(
                PGPEncryptedData.AES_128, withIntegrityCheck, new SecureRandom(),
                "BC"); //BAsic Code
        cPk.addMethod(publicKey);

        byte[] bytes = bOut.toByteArray();

        OutputStream cOut = cPk.open(out, bytes.length);

        cOut.write(bytes); // obtain the actual bytes from the compressed stream

        cOut.close();

        out.close();

        byte[] encOutByteArray=encOut.toByteArray();
        return encOutByteArray;
        }
        else
        {
        	 PGPEncryptedDataGenerator cPk = new PGPEncryptedDataGenerator(
                     PGPEncryptedData.CAST5, withIntegrityCheck, new SecureRandom(),
                     "BC");
        	 cPk.addMethod(publicKey);

             byte[] bytes = bOut.toByteArray();

             OutputStream cOut = cPk.open(out, bytes.length);

             cOut.write(bytes); // obtain the actual bytes from the compressed stream

             cOut.close();

             out.close();

             byte[] encOutByteArray=encOut.toByteArray();
             return encOutByteArray;
        }
    }
    
    /**
     * Simple PGP encryptor between String.
     * 
     * @param clearData
     *            The test to be encrypted
     * @param public key
     *            The pass phrase (key). This method assumes that the key is a
     *            simple pass phrase, and does not yet support RSA or more
     *            sophisiticated keying.
     * @param encryptionType
     * 			  encryption type takes input as AES or blank           
     * @param fileName
     *            File name. This is used in the Literal Data Packet (tag 11)
     *            which is really inly important if the data is to be related to
     *            a file to be recovered later. Because this routine does not
     *            know the source of the information, the caller can set
     *            something here for file name use that will be carried. If this
     *            routine is being used to encrypt SOAP MIME bodies, for
     *            example, use the file name from the MIME type, if applicable.
     *            Or anything else appropriate.
     * 
     * @param armor
     * 
     * @return encrypted data in String.
     * @exception IOException
     * @exception PGPException
     * @exception NoSuchProviderException
     */
    public static String PGPEncryptString(String plainText,String encryptionType,PGPPublicKey encKey,
            String fileName,boolean withIntegrityCheck, boolean armor)
            throws IOException, PGPException, NoSuchProviderException {
		
		Security.addProvider(new BouncyCastleProvider());
		
        if (fileName == null) {
            fileName = PGPLiteralData.CONSOLE;
        }
        byte[] clearData=plainText.getBytes();
        ByteArrayOutputStream encOut = new ByteArrayOutputStream();

        OutputStream out = encOut;
        if (armor) {
            out = new ArmoredOutputStream(out);
        }

        ByteArrayOutputStream bOut = new ByteArrayOutputStream();

        PGPCompressedDataGenerator comData = new PGPCompressedDataGenerator(
                PGPCompressedDataGenerator.ZIP);
        OutputStream cos = comData.open(bOut); // open it with the final
        // destination
        PGPLiteralDataGenerator lData = new PGPLiteralDataGenerator();

        // we want to generate compressed data. This might be a user option
        // later,
        // in which case we would pass in bOut.
        OutputStream pOut = lData.open(cos, // the compressed output stream
                PGPLiteralData.BINARY, fileName, // "filename" to store
                clearData.length, // length of clear data
                new Date() // current time
                );
        
      
        pOut.write(clearData);

        lData.close();
        comData.close();
        if(encryptionType.equals("AES"))
        {
        PGPEncryptedDataGenerator cPk = new PGPEncryptedDataGenerator(
                PGPEncryptedData.AES_128, withIntegrityCheck, new SecureRandom(),
                "BC"); //BAsic Code
        cPk.addMethod(encKey);

        byte[] bytes = bOut.toByteArray();

        OutputStream cOut = cPk.open(out, bytes.length);

        cOut.write(bytes); // obtain the actual bytes from the compressed stream

        cOut.close();

        out.close();

        byte[] encOutByteArray=encOut.toByteArray();
        return new String(encOutByteArray);
        }
        else
        {
        	 PGPEncryptedDataGenerator cPk = new PGPEncryptedDataGenerator(
                     PGPEncryptedData.CAST5, withIntegrityCheck, new SecureRandom(),
                     "BC");
        	 cPk.addMethod(encKey);

             byte[] bytes = bOut.toByteArray();

             OutputStream cOut = cPk.open(out, bytes.length);

             cOut.write(bytes); // obtain the actual bytes from the compressed stream

             cOut.close();

             out.close();

             byte[] encOutByteArray=encOut.toByteArray();
             return new String(encOutByteArray);
        }
        
       
       
    }
    
    /**
     * Simple PGP decryptor between String.
     * 
     * @param encryptedData
     *            The data to be encrypted
     * @param secretKeyFileStream
     *			   secretkeyfilestream is used to locate the secret key file location.            
     * @param passwordstring
     *            it is used for finding the secret key
     * 
     * @return decrypted data into string.
     * @exception IOException
     * @exception PGPException
     * @exception NoSuchProviderException
     */
    public static String pgpDecryptString(String encryptedString, InputStream secretKeyFileStream, String passwordString)
            throws IOException, PGPException, NoSuchProviderException 
	{
    
		char[] password=passwordString.toCharArray();
		Security.addProvider(new BouncyCastleProvider());
		byte[] encrypted=encryptedString.getBytes();
        InputStream in = new ByteArrayInputStream(encrypted);

        in = PGPUtil.getDecoderStream(in);

        PGPObjectFactory pgpF = new PGPObjectFactory(in);
        PGPEncryptedDataList enc = null;
        Object o = pgpF.nextObject();

        //
        // the first object might be a PGP marker packet.
        //
        if (o instanceof PGPEncryptedDataList) {
            enc = (PGPEncryptedDataList) o;
        } else {
            enc = (PGPEncryptedDataList) pgpF.nextObject();
        }



        //
        // find the secret key
        //
        Iterator it = enc.getEncryptedDataObjects();
        PGPPrivateKey sKey = null;
        PGPPublicKeyEncryptedData pbe = null;
        PGPSecretKeyRingCollection pgpSec = new PGPSecretKeyRingCollection(
                PGPUtil.getDecoderStream(secretKeyFileStream));

        while (sKey == null && it.hasNext()) {
            pbe = (PGPPublicKeyEncryptedData) it.next();

            sKey = findSecretKey(pgpSec, pbe.getKeyID(), password);
        }

        if (sKey == null) {
            throw new IllegalArgumentException(
                    "secret key for message not found.");
        }

        InputStream clear = pbe.getDataStream(sKey, "BC");



        PGPObjectFactory pgpFact = new PGPObjectFactory(clear);

        PGPCompressedData cData = (PGPCompressedData) pgpFact.nextObject();

        pgpFact = new PGPObjectFactory(cData.getDataStream());

        PGPLiteralData ld = (PGPLiteralData) pgpFact.nextObject();

        InputStream unc = ld.getInputStream();

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        int ch;

        while ((ch = unc.read()) >= 0) {
            out.write(ch);

        }

        byte[] returnBytes = out.toByteArray();
        out.close();
        return new String(returnBytes);
    }
    
    /**
     * Simple PGP decryptor between byte array.
     * 
     * @param encryptedData
     *            The data to be encrypted
     * @param secretKeyFileStream
     *			   secretkeyfilestream is used to locate the secret key file location.            
     * @param passwordstring
     *            it is used for finding the secret key
     * 
     * @return decrypted data into byte array.
     * @exception IOException
     * @exception PGPException
     * @exception NoSuchProviderException
     */
    public static byte[] pgpDecryptByte(byte[] encryptedBytes, InputStream secretKeyFileStream, String passwordString)
            throws IOException, PGPException, NoSuchProviderException 
	{
    
		char[] password=passwordString.toCharArray();
		Security.addProvider(new BouncyCastleProvider());
		
        InputStream in = new ByteArrayInputStream(encryptedBytes);

        in = PGPUtil.getDecoderStream(in);

        PGPObjectFactory pgpF = new PGPObjectFactory(in);
        PGPEncryptedDataList enc = null;
        Object o = pgpF.nextObject();

        //
        // the first object might be a PGP marker packet.
        //
        if (o instanceof PGPEncryptedDataList) {
            enc = (PGPEncryptedDataList) o;
        } else {
            enc = (PGPEncryptedDataList) pgpF.nextObject();
        }



        //
        // find the secret key
        //
        Iterator it = enc.getEncryptedDataObjects();
        PGPPrivateKey sKey = null;
        PGPPublicKeyEncryptedData pbe = null;
        PGPSecretKeyRingCollection pgpSec = new PGPSecretKeyRingCollection(
                PGPUtil.getDecoderStream(secretKeyFileStream));

        while (sKey == null && it.hasNext()) {
            pbe = (PGPPublicKeyEncryptedData) it.next();

            sKey = findSecretKey(pgpSec, pbe.getKeyID(), password);
        }

        if (sKey == null) {
            throw new IllegalArgumentException(
                    "secret key for message not found.");
        }

        InputStream clear = pbe.getDataStream(sKey, "BC");



        PGPObjectFactory pgpFact = new PGPObjectFactory(clear);

        PGPCompressedData cData = (PGPCompressedData) pgpFact.nextObject();

        pgpFact = new PGPObjectFactory(cData.getDataStream());

        PGPLiteralData ld = (PGPLiteralData) pgpFact.nextObject();

        InputStream unc = ld.getInputStream();

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        int ch;

        while ((ch = unc.read()) >= 0) {
            out.write(ch);

        }

        byte[] returnBytes = out.toByteArray();
        out.close();
        return returnBytes;
    }
    
    private static PGPPrivateKey findSecretKey(
            PGPSecretKeyRingCollection pgpSec, long keyID, char[] pass)
            throws PGPException, NoSuchProviderException {
        PGPSecretKey pgpSecKey = pgpSec.getSecretKey(keyID);

        if (pgpSecKey == null) {
            return null;
        }

        return pgpSecKey.extractPrivateKey(pass, "BC");
    }
	
	public static PGPPublicKey readPublicKey(InputStream in)
            throws IOException, PGPException {
        in = PGPUtil.getDecoderStream(in);

        PGPPublicKeyRingCollection pgpPub = new PGPPublicKeyRingCollection(in);

        //
        // we just loop through the collection till we find a key suitable for
        // encryption, in the real
        // world you would probably want to be a bit smarter about this.
        //

        //
        // iterate through the key rings.
        //
        Iterator rIt = pgpPub.getKeyRings();

        while (rIt.hasNext()) {
            PGPPublicKeyRing kRing = (PGPPublicKeyRing) rIt.next();
            Iterator kIt = kRing.getPublicKeys();

            while (kIt.hasNext()) {
                PGPPublicKey k = (PGPPublicKey) kIt.next();

                if (k.isEncryptionKey()) {
                    return k;
                }
            }
        }

        throw new IllegalArgumentException(
                "Can't find encryption key in key ring.");
    }
	
	public static PGPSecretKey readSecretKey(InputStream in)
            throws IOException, PGPException {
        in = PGPUtil.getDecoderStream(in);

        
       PGPSecretKeyRingCollection pgpSec=new PGPSecretKeyRingCollection(in);
       
       Iterator keyRingIter = pgpSec.getKeyRings();
       while (keyRingIter.hasNext())
       {
           PGPSecretKeyRing keyRing = (PGPSecretKeyRing)keyRingIter.next();

           Iterator keyIter = keyRing.getSecretKeys();
           while (keyIter.hasNext())
           {
               PGPSecretKey key = (PGPSecretKey)keyIter.next();

               if (key.isSigningKey())
               {
                   return key;
                   
               }
           }
       }

       throw new IllegalArgumentException("Can't find signing key in key ring.");

}
	
	 /**
     * Simple PGP key pair generator.
     * 
     * @param publicKeyFile
     *            it is location of the public key file
     * @param privateKeyFile
     *			   it is location of the private key file.            
     * @param id
     * 				it is id of the public key
     * @param passwordstring
     *            it is used for finding the secret key
     * 
     * @return public key data into String.
     * @exception IOException
     * @exception PGPException
     * @exception NoSuchProviderException
     * @exception InvalidKeyException
     * @exception SignatureException
     */
	public static String  genKeyPair(String publicKeyFile,String privateKeyFile,String id, String password,boolean isArmored) throws InvalidKeyException, NoSuchProviderException, SignatureException, IOException, PGPException, NoSuchAlgorithmException 
	{

		Security.addProvider(new BouncyCastleProvider());
		
		KeyPairGenerator    kpg = KeyPairGenerator.getInstance("RSA", "BC");
			
		kpg.initialize(1024);

		KeyPair kp = kpg.generateKeyPair();

		FileOutputStream    out1 = new FileOutputStream(privateKeyFile);
		FileOutputStream    out2 = new FileOutputStream(publicKeyFile);

		CryptLib.exportKeyPair(out1, out2, kp.getPublic(), kp.getPrivate(), id, password.toCharArray(), isArmored);
			
		byte[] pubkeyBytes = IOUtils.toByteArray(new FileInputStream(publicKeyFile));
		
		String byetesencodedString=org.bouncycastle.util.encoders.Base64.toBase64String(pubkeyBytes);
		return byetesencodedString;

	}
	
	public  static void exportKeyPair(OutputStream secretOut, OutputStream publicOut, PublicKey publicKey,
			PrivateKey privateKey, String identity, char[] passPhrase, boolean armor)
			throws IOException, InvalidKeyException, NoSuchProviderException, SignatureException, PGPException {
		if (armor) {
			secretOut = new ArmoredOutputStream(secretOut);
		}

		PGPPublicKey publicKey1 = (new JcaPGPKeyConverter().getPGPPublicKey(PGPPublicKey.RSA_GENERAL, publicKey, new Date()));
		RSAPrivateCrtKey rsK = (RSAPrivateCrtKey) privateKey;
		RSASecretBCPGKey privPk = new RSASecretBCPGKey(rsK.getPrivateExponent(), rsK.getPrimeP(), rsK.getPrimeQ());
		PGPPrivateKey privateKey1 = new PGPPrivateKey(publicKey1.getKeyID(), publicKey1.getPublicKeyPacket(), privPk);

		PGPDigestCalculator sha1Calc = new JcaPGPDigestCalculatorProviderBuilder().build().get(HashAlgorithmTags.SHA1);
		PGPKeyPair keyPair = new PGPKeyPair(publicKey1, privateKey1);
		PGPSecretKey secretKey = new PGPSecretKey(PGPSignature.DEFAULT_CERTIFICATION, keyPair, identity, sha1Calc, null,
				null, new JcaPGPContentSignerBuilder(keyPair.getPublicKey().getAlgorithm(), HashAlgorithmTags.SHA1),
				new JcePBESecretKeyEncryptorBuilder(PGPEncryptedData.CAST5, sha1Calc).setProvider("BC")
						.build(passPhrase));

		secretKey.encode(secretOut);
		secretOut.close();

		if (armor) {
			publicOut = new ArmoredOutputStream(publicOut);
		}

		PGPPublicKey key = secretKey.getPublicKey();

		key.encode(publicOut);

		publicOut.close();
	}
    
    

}