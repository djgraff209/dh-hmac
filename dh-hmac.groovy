import java.io.*;
import java.math.BigInteger;
import java.security.*;
import java.security.spec.*;
import java.security.interfaces.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import javax.crypto.interfaces.*;
import com.sun.crypto.provider.SunJCE;
import javax.xml.bind.DatatypeConverter

AlgorithmParameterGenerator paramGen = AlgorithmParameterGenerator.getInstance("DH");
paramGen.init(512);
AlgorithmParameters params = paramGen.generateParameters();
DHParameterSpec dhSkipParamSpec = (DHParameterSpec)params.getParameterSpec (DHParameterSpec.class);

System.out.println("ALICE: Generate DH keypair ...");
KeyPairGenerator aliceKpairGen = KeyPairGenerator.getInstance("DH");
aliceKpairGen.initialize(dhSkipParamSpec);
KeyPair aliceKpair = aliceKpairGen.generateKeyPair();

// Alice creates and initializes her DH KeyAgreement object
System.out.println("ALICE: Initialization ...");
KeyAgreement aliceKeyAgree = KeyAgreement.getInstance("DH");
aliceKeyAgree.init(aliceKpair.getPrivate());

// Alice encodes her public key, and sends it over to Bob.
byte[] alicePubKeyEnc = aliceKpair.getPublic().getEncoded();

/*
 * Let's turn over to Bob. Bob has received Alice's public key
 * in encoded format.
 * He instantiates a DH public key from the encoded key material.
 */
KeyFactory bobKeyFac = KeyFactory.getInstance("DH");
X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(alicePubKeyEnc);
PublicKey alicePubKey = bobKeyFac.generatePublic(x509KeySpec);

/*
 * Bob gets the DH parameters associated with Alice's public key.
 * He must use the same parameters when he generates his own key
 * pair.
 */
DHParameterSpec dhParamSpec = ((DHPublicKey)alicePubKey).getParams();

// Bob creates his own DH key pair
System.out.println("BOB: Generate DH keypair ...");
KeyPairGenerator bobKpairGen = KeyPairGenerator.getInstance("DH");
bobKpairGen.initialize(dhParamSpec);
KeyPair bobKpair = bobKpairGen.generateKeyPair();

// Bob creates and initializes his DH KeyAgreement object
System.out.println("BOB: Initialization ...");
KeyAgreement bobKeyAgree = KeyAgreement.getInstance("DH");
bobKeyAgree.init(bobKpair.getPrivate());

// Bob encodes his public key, and sends it over to Alice.
byte[] bobPubKeyEnc = bobKpair.getPublic().getEncoded();

/*
 * Alice uses Bob's public key for the first (and only) phase
 * of her version of the DH
 * protocol.
 * Before she can do so, she has to instantiate a DH public key
 * from Bob's encoded key material.
 */
KeyFactory aliceKeyFac = KeyFactory.getInstance("DH");
x509KeySpec = new X509EncodedKeySpec(bobPubKeyEnc);
PublicKey bobPubKey = aliceKeyFac.generatePublic(x509KeySpec);
System.out.println("ALICE: Execute PHASE1 ...");
aliceKeyAgree.doPhase(bobPubKey, true);

/*
 * Bob uses Alice's public key for the first (and only) phase
 * of his version of the DH
 * protocol.
 */
System.out.println("BOB: Execute PHASE1 ...");
bobKeyAgree.doPhase(alicePubKey, true);

/*
 * At this stage, both Alice and Bob have completed the DH key
 * agreement protocol.
 * Both generate the (same) shared secret.
 */
byte[] aliceSharedSecret = aliceKeyAgree.generateSecret();
int aliceLen = aliceSharedSecret.length;

byte[] bobSharedSecret = new byte[aliceLen];
int bobLen;
try {
    // show example of what happens if you
    // provide an output buffer that is too short
    bobLen = bobKeyAgree.generateSecret(bobSharedSecret, 1);
} catch (ShortBufferException e) {
    System.out.println(e.getMessage());
}
// provide output buffer of required size
bobLen = bobKeyAgree.generateSecret(bobSharedSecret, 0);

System.out.println("Alice secret: " + aliceSharedSecret.encodeHex());
System.out.println("Bob secret: " + bobSharedSecret.encodeHex());

if (!java.util.Arrays.equals(aliceSharedSecret, bobSharedSecret))
    throw new Exception("Shared secrets differ");
System.out.println("Shared secrets are the same");

bobKeyAgree.doPhase(alicePubKey, true);

SecretKeySpec bobSigningKey= new SecretKeySpec(bobKeyAgree.generateSecret(), "HmacSHA512")
Mac bobMac= Mac.getInstance("HmacSHA512")
bobMac.init(bobSigningKey)

aliceKeyAgree.doPhase(bobPubKey, true);
SecretKeySpec aliceSigningKey= new SecretKeySpec(aliceKeyAgree.generateSecret(), "HmacSHA512")
Mac aliceMac= Mac.getInstance("HmacSHA512")
aliceMac.init(aliceSigningKey)

byte[] aliceResult= aliceMac.doFinal("The quick brown fox jumped over the lazy dog".getBytes());

byte[] bobResult= bobMac.doFinal("The quick brown fox jumped over the lazy dog".getBytes())
assert aliceResult == bobResult
println "done"


