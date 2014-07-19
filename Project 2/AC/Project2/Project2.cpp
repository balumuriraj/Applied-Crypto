#include "RSA.h"
#include "BigInt.h"
#include <cmath>
#include<iostream>
#include<string>
#include<cstdlib>
#include<time.h>
#define RAND_LIMIT32 0x7FFFFFFF
using namespace RSAUtil;
/*
Declaring RSA variable to be used for blind signature and also functions which are used for blind signature them. 
*/
RSA signersRSA;
BigInt Requester(BigInt, BigInt, BigInt);
BigInt Signer(BigInt);

int main(int argc, char*argv[]){    
  
	/*
	TASK 1: Perform encryption and Decryption each using the RSA routines provided here. They don’t necessarily have to be part of the same code
	*/
	int count = 10;
	int i=0;
	std::string result;
	BigInt randMessage[10];
	
	std::cout<<"********************************************************************************************************************************************************************"<<std::endl;
	std::cout<<"TASK 1a: Create 10 instances of the RSA class without giving arguments, generate random message or assign messages, and perform encryption through each of the 10 classes. "<<std::endl;
	std::cout<<"********************************************************************************************************************************************************************"<<std::endl;
	//initializing at once as everytime RSA is called srand is called internally and reseting the random function
	for(i=0;i<count;i++)
	{
	   randMessage[i] = int(((double)std::rand()/RAND_MAX)*RAND_LIMIT32);
	}
	for(i=0;i<count;i++)
	{
	  RSA myRSA;
	  BigInt message, cipher, deciphered;
	  message = randMessage[i];
	
	  //encrypting
	  cipher = myRSA.encrypt(message);
	  //decrypting
	  deciphered = myRSA.decrypt(cipher);
	  
	  //Checking if the decrypted value is equal to original value 
	  if(message == deciphered)
	  {
	    result = "success";
	  }
	  else
	  {
	    result = "failed";
	  }
	  std::cout<<"Instance:"<<i<<"\tmessage: "<<message.toHexString()<<"\tcipher: "<<cipher.toHexString()<<"\tdeciphered: "<<deciphered.toHexString()<<"\tverification-result:"<<result<<std::endl;
	}
	std::cout<<"********************************************************************************************************************************************************************"<<std::endl;
	std::cout<<"TASK 1b: Create 5 instances of the RSA class by passing a large prime number [p](> 30,000), and perform encryption decryption. "<<std::endl;
	std::cout<<"********************************************************************************************************************************************************************"<<std::endl;
	
	count =  5;
	//Initializing some primes and non-primes to be used by following tasks.
	unsigned long int setOfLargePrimes[] = {103919, 103951, 103963, 103967,103969, 104677 ,104681 ,104683 ,104693 ,104701 ,104707 ,104711 ,104717 ,104723 ,104729};
	unsigned long int setOfNonPrimes[] = {40000, 31000, 42000, 45000, 50000, 48000,60000,80000,70000,90000,99000};
	
	
	//iterating 5 time for question 1b
	for(i=0;i<count;i++)
	{
	  //giving one primenumber as input to the RSA
	  RSA rsaInstance(setOfLargePrimes[i]);
	  BigInt message, cipher, deciphered;
	  message = randMessage[i];
	 
	  //decrypting and encrypting 
	  cipher = rsaInstance.encrypt(message);
	  deciphered = rsaInstance.decrypt(cipher);
	  
	  //Checking if the decrypted value is equal to original value 
	  if(message == deciphered)
	  {
	    result = "success";
	  }
	  else
	  {
	    result = "failed";
	  }
	  
	  std::cout<<"Instance:"<<i<<"\tmessage: "<<message.toHexString()<<"\tcipher: "<<cipher.toHexString()<<"\tdeciphered: "<<deciphered.toHexString()<<"\tverification-result:"<<result<<std::endl;
	
	}
	
	std::cout<<"********************************************************************************************************************************************************************"<<std::endl;
	std::cout<<"TASK 1c: Create 5 instances of the RSA class by passing 2 large prime numbers [p,q] (> 30,000) and perform encryption decryption "<<std::endl;
	std::cout<<"********************************************************************************************************************************************************************"<<std::endl;
	
	for(i=0;i<count;i++)
	{
	  //Intializing RSA with two primenumbers
	  RSA rsaInstance(setOfLargePrimes[2*i], setOfLargePrimes[2*i+1]);
	  BigInt message, cipher, deciphered;
	  
	  message = randMessage[i];
	  
	  //encrypting and decrypting
	  cipher = rsaInstance.encrypt(message);
	  deciphered = rsaInstance.decrypt(cipher);
	 
	  //Checking if the decrypted value is equal to original value 
	  if(message == deciphered)
	  {
	    result = "success";
	  }
	  else
	  {
	    result = "failed";
	  }
	  
	  std::cout<<"Instance:"<<i<<"\tmessage: "<<message.toHexString()<<"\tcipher: "<<cipher.toHexString()<<"\tdeciphered: "<<deciphered.toHexString()<<"\tverification-result:"<<result<<std::endl;
	
	}
	
	std::cout<<"********************************************************************************************************************************************************************"<<std::endl;
	std::cout<<"TASK 1d: Create 10 instances of the RSA class by passing 2 large non prime numbers (> 30,000) and perform encryption decryption. In most of the cases the message should not get decrypted correctly.  "<<std::endl;
	std::cout<<"********************************************************************************************************************************************************************"<<std::endl;
	
	for(i=0;i<10;i++)
	{
	  //Creating RSA with non primes. 
	  RSA rsaInstance(setOfNonPrimes[i], setOfNonPrimes[i+1]);
	  BigInt message, cipher, deciphered;
	  
	  message = randMessage[i];
	   //encrypting and decrypting
	  cipher = rsaInstance.encrypt(message);
	  deciphered = rsaInstance.decrypt(cipher);
	 
	  //Checking if the decrypted value is equal to original value 
	  if(message == deciphered)
	  {
	    result = "success";
	  }
	  else
	  {
	    result = "failed";
	  }
	  
	  std::cout<<"Instance:"<<i<<"\tmessage: "<<message.toHexString()<<"\tcipher: "<<cipher.toHexString()<<"\tdeciphered: "<<deciphered.toHexString()<<"\tverification-result:"<<result<<std::endl;
	
	}
	
	/*
	TASK 2: Challenge Response: Scheme 0
	*/
	std::cout<<"********************************************************************************************************************************************************************"<<std::endl;
	std::cout<<" TASK 2: Challenge Response Scheme 0 "<<std::endl;
	std::cout<<"********************************************************************************************************************************************************************"<<std::endl;
	
	{
	  RSA RSA1, RSA2;
	  
	  //Assigning RSA1 public key and Modulus to RSA2 
	  BigInt publicKey = RSA1.getPublicKey();
	  BigInt modulus = RSA1.getModulus();
	  RSA2.setPublicKey(publicKey);
	  RSA2.setN(modulus);
	  
	  //generating random message
	  BigInt message, cipher, deciphered;
	  message = int(((double)std::rand()/RAND_MAX)*RAND_LIMIT32);
	  
	  
	  //encrypting with RSA2 i.e RSA1's public key
	  cipher = RSA2.encrypt(message);
	  //decrypting with RSA1 i.e RSA1's private key
	  deciphered = RSA1.decrypt(cipher);
	  
	 //Checking if the decrypted value is equal to original value 
	  if(message == deciphered)
	  {
	    result = "success";
	  }
	  else
	  {
	    result = "failed";
	  }
	  
	  std::cout<<"Instance:"<<i<<"\tmessage: "<<message.toHexString()<<"\tcipher: "<<cipher.toHexString()<<"\tdeciphered: "<<deciphered.toHexString()<<"\tverification-result:"<<result<<std::endl;
	
	}
	
	/*
	TASK 3: Blind Signature
	*/
	std::cout<<"********************************************************************************************************************************************************************"<<std::endl;
	std::cout<<" TASK 3: Blind Signature  "<<std::endl;
	std::cout<<"********************************************************************************************************************************************************************"<<std::endl;
	
	{
	  //Random message requester want to send with signers signature
	  BigInt message = int(((double)std::rand()/RAND_MAX)*RAND_LIMIT32);
	  
	  //Passing signers public key to the requester so that he can generate the blind factor
	  BigInt signedMessage =  Requester(message, signersRSA.getPublicKey(), signersRSA.getModulus());
	  BigInt deciphered = signersRSA.encrypt(signedMessage);
	  
	  std::cout<<"Signed Message without blindfactor:" << signedMessage.toHexString() <<std::endl;
	  
	  std::cout<<" Message Decrypted:" << deciphered.toHexString() <<std::endl;
	  
	  //Checking if the decrypted value is equal to original value 
	  if(message == deciphered)
	  {
	    std::cout<<"Blind Signature successfully implemented"<<std::endl;
	  }
	  else
	  {
	    std::cout<<"Blind Signature implementation failed"<<std::endl;
	  }
	  
	 
	}
	

}

/*
This method performs all the alice actions. 
*/
BigInt Requester(BigInt message, BigInt signersPubKey, BigInt modulus)
{
    //Initializing all the variables required
    BigInt blindingFactor, encBlindingFactor, blindingFactorInverse, signedMessageWithBlindingFactor, encMessageWithBlindingFactor, messageWithSign,originalMessage;
    
    //RSA which will have signers publicKey and modulus
    RSA requesterRSA;
    requesterRSA.setN(modulus);
    requesterRSA.setPublicKey(signersPubKey);
    
    //Generating a random blindfactor
    blindingFactor = int(((double)std::rand()/RAND_MAX)*RAND_LIMIT32);
    //Blind factor modulus inverse is calculated
    blindingFactorInverse = modInverse(blindingFactor, modulus);
    
    
    
    //Encrypting the blinding factor with signers public key
    encBlindingFactor = requesterRSA.encrypt(blindingFactor);
    //appending original message to the encrypted blindfactor
    encMessageWithBlindingFactor = encBlindingFactor*message;
    encMessageWithBlindingFactor = encMessageWithBlindingFactor%modulus;
    
    //sending the encyrpted blindfactor and origin message to signer as product and get back the signed message with blinding factor
    signedMessageWithBlindingFactor = Signer(encMessageWithBlindingFactor);
    
    std::cout<<"Alice's(Sender's) Random Message generated:  " << message.toHexString() <<std::endl;
    std::cout<<"Encrypted Message sent to Bob with blindfactor and original message:" << encMessageWithBlindingFactor.toHexString() <<std::endl;
    
    //removing the blindfactor
    messageWithSign = (signedMessageWithBlindingFactor*blindingFactorInverse) % modulus;
    std::cout<<"Signed Message recieved from Bob with blindfactor and original message:" << signedMessageWithBlindingFactor.toHexString() <<std::endl;
    return messageWithSign;
}  

BigInt	Signer(BigInt messageWithBlindFactor)
{
   return signersRSA.decrypt(messageWithBlindFactor);
}
  
