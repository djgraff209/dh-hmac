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
import java.nio.channels.*;
import java.util.concurrent.CountDownLatch

def Pipe pipe= Pipe.open();
final DataOutputStream sinkStream= new DataOutputStream(Channels.newOutputStream(pipe.sink().configureBlocking(true)));
final DataInputStream sourceStream= new DataInputStream(Channels.newInputStream(pipe.source().configureBlocking(true)));
def latch= new CountDownLatch(2)

class Alice implements Runnable {
    DataOutputStream sinkStream
    DataInputStream sourceStream
    String message;
    CountDownLatch latch;

    @Override
    public void run() {
        try {
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
            sinkStream.writeInt(alicePubKeyEnc.length);
            sinkStream.write(alicePubKeyEnc, 0, alicePubKeyEnc.length);
    
            int inboundLen= sourceStream.readInt();
            byte[] bobPubKeyEnc= new byte[inboundLen]
            sourceStream.readFully(bobPubKeyEnc, 0, inboundLen);
    
            /*
             * Alice uses Bob's public key for the first (and only) phase
             * of her version of the DH
             * protocol.
             * Before she can do so, she has to instantiate a DH public key
             * from Bob's encoded key material.
             */
            KeyFactory aliceKeyFac = KeyFactory.getInstance("DH");
            def x509KeySpec = new X509EncodedKeySpec(bobPubKeyEnc);
            PublicKey bobPubKey = aliceKeyFac.generatePublic(x509KeySpec);
            System.out.println("ALICE: Execute PHASE1 ...");
            aliceKeyAgree.doPhase(bobPubKey, true);
    
            SecretKeySpec aliceSigningKey= new SecretKeySpec(aliceKeyAgree.generateSecret(), "HmacSHA512")
            Mac aliceMac= Mac.getInstance("HmacSHA512")
            aliceMac.init(aliceSigningKey)
    
            byte[] aliceResult= aliceMac.doFinal(message.getBytes());
            sinkStream.writeInt(aliceResult.length)
            sinkStream.write(aliceResult, 0, aliceResult.length);
            sinkStream.writeUTF(message);
            
            println "Bob said: "+sourceStream.readUTF()
        }
        finally {
            latch.countDown()
        }
    }
}

class Bob implements Runnable {
    DataOutputStream sinkStream
    DataInputStream sourceStream
    CountDownLatch latch;

    @Override
    public void run() {
        try {
            int inboundLen= sourceStream.readInt();
            byte[] alicePubKeyEnc= new byte[inboundLen]
            sourceStream.readFully(alicePubKeyEnc, 0, inboundLen);
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
            sinkStream.writeInt(bobPubKeyEnc.length);
            sinkStream.write(bobPubKeyEnc, 0, bobPubKeyEnc.length);
    
            /*
             * Bob uses Alice's public key for the first (and only) phase
             * of his version of the DH
             * protocol.
             */
            System.out.println("BOB: Execute PHASE1 ...");
            bobKeyAgree.doPhase(alicePubKey, true);
    
            SecretKeySpec bobSigningKey= new SecretKeySpec(bobKeyAgree.generateSecret(), "HmacSHA512")
            Mac bobMac= Mac.getInstance("HmacSHA512")
            bobMac.init(bobSigningKey)
    
            
            byte[] aliceResult= new byte[sourceStream.readInt()];
            sourceStream.readFully(aliceResult)
            def message = sourceStream.readUTF();
            
            byte[] bobResult= bobMac.doFinal(message.getBytes())
            assert aliceResult == bobResult
            sinkStream.writeUTF("OK")
        }
        finally {
            latch.countDown()
        }
    }
}

Thread t1= new Thread(new Alice(message: "The quick brown fox jumped over the lazy dog", sinkStream: sinkStream, sourceStream: sourceStream, latch: latch))
Thread t2= new Thread(new Bob(sinkStream: sinkStream, sourceStream: sourceStream, latch: latch))
t1.start()
t2.start()

latch.await()
println "done"


