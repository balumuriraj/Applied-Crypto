package edu.asu.acproj;

import java.io.BufferedInputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.UnrecoverableEntryException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Enumeration;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import sun.misc.BASE64Encoder;

public class CertOps {

	public void printCert() throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException, UnrecoverableEntryException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException
	{
		String password = "raghu";

		InputStream raghupubfile = new FileInputStream("Certs//Raghupub.cer");
		BufferedInputStream raghupub = new BufferedInputStream(raghupubfile);

		InputStream CApubfile = new FileInputStream("Certs//Trustcenter.cer");
		BufferedInputStream CApub = new BufferedInputStream(CApubfile);

		InputStream raghuprivfile = new FileInputStream("Certs//Raghupri.pfx");
		BufferedInputStream raghupriv = new BufferedInputStream(raghuprivfile);

		KeyStore kstore = KeyStore.getInstance("pkcs12");
		kstore.load(raghupriv, password.toCharArray());

		CertificateFactory certfact = CertificateFactory.getInstance("X.509");
		Certificate raghupubcert = null;
		Certificate CApubcert = null;

		while(raghupub.available() > 0){
			raghupubcert = certfact.generateCertificate(raghupub);
		}

		while(CApub.available() > 0){
			CApubcert = certfact.generateCertificate(CApub);
		}

		PublicKey raghupubkey = raghupubcert.getPublicKey();
		PublicKey CApubkey = CApubcert.getPublicKey();

		System.out.println("------------------------------Verify Raghu’s certificate--------------------------");
		System.out.println();
		System.out.println("1. Print the certificate");
		System.out.println("-------------------------------------------------------------------------");
		try {
			raghupubcert.verify(CApubkey);
			System.out.println("Verified Raghu's Certificate!");
		} catch (InvalidKeyException | NoSuchProviderException
				| SignatureException e) {
			// TODO Auto-generated catch block
			System.out.println("Error while verifying Raghu's Certificate!");
		}
		System.out.println(raghupubcert);

		System.out.println("\n2. Print Raghu’s public and private key");
		System.out.println("-------------------------------------------------------------------------");
		System.out.println("Raghu's Public Key is: ");
		System.out.println(raghupubkey);
		byte[] rpubkbytes = raghupubkey.getEncoded();
		StringBuilder rpubk = new StringBuilder();

		for(byte b : rpubkbytes){
			rpubk.append(String.format("%02X",b));
		}
		System.out.println("In hex format: " +rpubk.toString());	 

		System.out.println("\nRaghu's Private Key is: ");
		Enumeration<String> aliases = kstore.aliases();
		KeyStore.PrivateKeyEntry rprivkEntry = null;
		while(aliases.hasMoreElements()) {
			String alias = (String)aliases.nextElement();
			if (kstore.isKeyEntry(alias)){
				rprivkEntry = (KeyStore.PrivateKeyEntry)kstore.getEntry(alias,new KeyStore.PasswordProtection(password.toCharArray()));
				break;
			}
		}
		PrivateKey raghuprivkey = rprivkEntry.getPrivateKey();
		System.out.println(raghuprivkey);
		byte[] rprivkbytes = raghuprivkey.getEncoded();
		StringBuilder rprivk = new StringBuilder();
		System.out.println();
		for(byte b : rprivkbytes){
			rprivk.append(String.format("%02X",b));
		}
		System.out.println("In hex format: " +rprivk.toString());	

		System.out.println("\n3. Print the public Key of Certification Authority.");
		System.out.println("-------------------------------------------------------------------------");
		System.out.println("Certification Authority's Public Key is: ");
		System.out.println(CApubkey);
		byte[] capubkbytes = CApubkey.getEncoded();
		StringBuilder capubk = new StringBuilder();
		System.out.println();
		for(byte b : capubkbytes){
			capubk.append(String.format("%02X",b));
		}
		System.out.println("In hex format: " +capubk.toString());	

		System.out.println("\n4. Print the signature on TA’s certificate.");
		System.out.println("-------------------------------------------------------------------------");
		System.out.println("Signature on TA’s certificate: ");
		X509Certificate xcert = (X509Certificate) raghupubcert;
		System.out.println(new BASE64Encoder().encode(xcert.getSignature()));
		byte[] xcbytes = CApubkey.getEncoded();
		StringBuilder xck = new StringBuilder();
		System.out.println();
		for(byte b : xcbytes){
			xck.append(String.format("%02X",b));
		}
		System.out.println("In hex format: " +xck.toString());	

		System.out.println("\n5. Encrypt and Decrypt the following string using RSA.");
		System.out.println("-------------------------------------------------------------------------");
		String plainText = "Our names are Satya Swaroop Boddu and MohanRaj Balumuri. We are enrolled in cse 539.";
		byte[] ciphertext = encrypt(plainText, raghupubkey);			
		String cleartext = decrypt(ciphertext, raghuprivkey);

		System.out.println("Cipher text: "+ new BASE64Encoder().encode(ciphertext));
		System.out.println("\nAfter Decryption: "+cleartext);
	}

	public byte[] encrypt(String data, PublicKey key) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException{
		Cipher aes = Cipher.getInstance("RSA/ECB/PKCS1Padding");
		aes.init(Cipher.ENCRYPT_MODE, key);
		byte[] ciphertext = aes.doFinal(data.getBytes());
		return ciphertext;
	}

	public String decrypt(byte[] ciphertext, PrivateKey key) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException{
		Cipher aes = Cipher.getInstance("RSA/ECB/PKCS1Padding");
		aes.init(Cipher.DECRYPT_MODE, key);
		String cleartext = new String(aes.doFinal(ciphertext));
		return cleartext;
	}

	public static void main(String[] args) {
		// TODO Auto-generated method stub

		CertOps c = new CertOps();

		try {
			c.printCert();
		} catch (KeyStoreException | NoSuchAlgorithmException | InvalidKeyException | NoSuchPaddingException | IllegalBlockSizeException | BadPaddingException
				| CertificateException | UnrecoverableEntryException | IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

}
