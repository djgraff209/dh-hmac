import java.io.*
import java.nio.channels.*
import java.security.*
import java.security.spec.*
import java.security.interfaces.*
import java.time.*
import java.util.concurrent.CountDownLatch
import javax.crypto.*
import javax.crypto.spec.*
import javax.crypto.interfaces.*


class Alice implements Runnable {
    Integer dhKeyLength
    DataOutputStream sinkStream
    DataInputStream sourceStream
    CountDownLatch latch
    String message
    
    KeyAgreement aliceKeyAgree
    Mac aliceMac

    private void establishKeyAgreement() {
        AlgorithmParameterGenerator paramGen = AlgorithmParameterGenerator.getInstance("DH")
        paramGen.init(dhKeyLength)
        AlgorithmParameters params = paramGen.generateParameters()
        DHParameterSpec dhParamSpec = (DHParameterSpec)params.getParameterSpec (DHParameterSpec.class)
        
        println "ALICE: Generate DH keypair ..."
        KeyPairGenerator aliceKpairGen = KeyPairGenerator.getInstance("DH")
        aliceKpairGen.initialize(dhParamSpec)
        KeyPair aliceKpair = aliceKpairGen.generateKeyPair()
        
        // Alice creates and initializes her DH KeyAgreement object
        println "ALICE: Initialization ..."
        KeyAgreement keyAgree = KeyAgreement.getInstance("DH")
        keyAgree.init(aliceKpair.getPrivate())
        
        // Alice encodes her public key, and sends it over to Bob.
        print "ALICE: Send public ... "
        sinkStream.writeUTF(aliceKpair.getPublic().getEncoded().encodeBase64().toString())

        // Read bob's public key
        byte[] bobPubKeyEnc= sourceStream.readUTF().decodeBase64()
        println "ALICE: ... Receive public"

        /*
         * Alice uses Bob's public key for the first (and only) phase
         * of her version of the DH
         * protocol.
         * Before she can do so, she has to instantiate a DH public key
         * from Bob's encoded key material.
         */
        KeyFactory bobKeyFac = KeyFactory.getInstance("DH")
        def x509KeySpec = new X509EncodedKeySpec(bobPubKeyEnc)
        PublicKey bobPubKey = bobKeyFac.generatePublic(x509KeySpec)
        println "ALICE: Execute PHASE1 ..."
        keyAgree.doPhase(bobPubKey, true)
        
        aliceKeyAgree= keyAgree
    }
    
    private void establishHmac() {
        // Create an instance of HmacSHA512 key generator
        KeyGenerator hmacKeyGenerator= KeyGenerator.getInstance("HmacSHA512")
        // generate HmacSHA512 key
        SecretKey aliceSigningKey= hmacKeyGenerator.generateKey()
        
        print "ALICE: Sending Mac Algo ${aliceSigningKey.algorithm} ... "
        sinkStream.writeUTF(aliceSigningKey.algorithm)

        // Create AES cipher to wrap the key
        Cipher cipher= Cipher.getInstance("AES")
        cipher.init(Cipher.WRAP_MODE, aliceKeyAgree.generateSecret("AES"))
        // Wrap & Transmit the key
        print "ALICE: Sending Mac SecretKey(${aliceSigningKey.algorithm}) ... "
        sinkStream.writeUTF(cipher.wrap(aliceSigningKey).encodeBase64().toString())

        // Create mac engine and initialize with key
        aliceMac= Mac.getInstance("HmacSHA512")
        aliceMac.init(aliceSigningKey)
    }

    @Override
    public void run() {
        try {
            establishKeyAgreement()
            establishHmac()

            def odtString= OffsetDateTime.now(ZoneOffset.UTC).toString()
            aliceMac.update(odtString.getBytes())

            // Create & write mac 
            def computedMac= aliceMac.doFinal(message.getBytes()).encodeBase64().toString()
            sinkStream.writeUTF(computedMac)
            print "ALICE: Sent Mac ${computedMac} ... "
            
            // Write message
            sinkStream.writeUTF(odtString)

            print "ALICE: Sent timestamp ${odtString} ... "
            sinkStream.writeUTF(message)

            print "ALICE: Sent message ${message} ... "
            
            // See what bob said
            println "ALICE: Bob said: ${sourceStream.readUTF()}"
        }
        finally {
            latch.countDown()
        }
    }
}

class Bob implements Runnable {
    DataOutputStream sinkStream
    DataInputStream sourceStream
    CountDownLatch latch

    KeyAgreement bobKeyAgree
    Mac bobMac

    private establishKeyAgreement() {
        byte[] alicePubKeyEnc= sourceStream.readUTF().decodeBase64()
        println "BOB: Receive public"

        /*
         * Let's turn over to Bob. Bob has received Alice's public key
         * in encoded format.
         * He instantiates a DH public key from the encoded key material.
         */
        KeyFactory bobKeyFac = KeyFactory.getInstance("DH")
        X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(alicePubKeyEnc)
        PublicKey alicePubKey = bobKeyFac.generatePublic(x509KeySpec)

        /*
         * Bob gets the DH parameters associated with Alice's public key.
         * He must use the same parameters when he generates his own key
         * pair.
         */
        DHParameterSpec dhParamSpec = ((DHPublicKey)alicePubKey).getParams()

        // Bob creates his own DH key pair
        println "BOB: Generate DH keypair ..."
        KeyPairGenerator bobKpairGen = KeyPairGenerator.getInstance("DH")
        bobKpairGen.initialize(dhParamSpec)
        KeyPair bobKpair = bobKpairGen.generateKeyPair()

        // Bob creates and initializes his DH KeyAgreement object
        println "BOB: Initialization ..."
        KeyAgreement keyAgree = KeyAgreement.getInstance("DH")
        keyAgree.init(bobKpair.getPrivate())

        // Bob encodes his public key, and sends it over to Alice.
        print "BOB: Write public key ... "
        sinkStream.writeUTF(bobKpair.getPublic().getEncoded().encodeBase64().toString())

        /*
         * Bob uses Alice's public key for the first (and only) phase
         * of his version of the DH
         * protocol.
         */
        println "BOB: Execute PHASE1 ..."
        keyAgree.doPhase(alicePubKey, true)
        bobKeyAgree= keyAgree
    }
    
    private establishHmac() {
        // Create cipher to unwrap secret key with
        Cipher cipher= Cipher.getInstance("AES")
        cipher.init(Cipher.UNWRAP_MODE, bobKeyAgree.generateSecret("AES"))
        
        String macAlgorithm = sourceStream.readUTF()
        println "BOB: Received Mac Algo ${macAlgorithm}"
        // Read and unwrap secret key
        SecretKey signingKey= cipher.unwrap(sourceStream.readUTF().decodeBase64(), macAlgorithm, Cipher.SECRET_KEY)
        println "BOB: Recieved Mac SecretKey(${signingKey.algorithm})"

        // Create mac engine
        bobMac= Mac.getInstance(macAlgorithm)
        // Initialize with the signing key
        bobMac.init(signingKey)
    }

    @Override
    public void run() {
        try {
            establishKeyAgreement()
            establishHmac()
    
            // Read the mac
            def computedMac= sourceStream.readUTF()
            println "BOB: Receved Mac ${computedMac}"
            byte[] aliceResult= computedMac.decodeBase64()
            
            // Read timestamp
            def odtString= sourceStream.readUTF()
            bobMac.update(odtString.getBytes())
            println "BOB: Received timestamp ${odtString}"
            
            // Read the message
            def message = sourceStream.readUTF()
            println "BOB: Received message ${message}"

            OffsetDateTime now= OffsetDateTime.now(ZoneOffset.UTC)
            OffsetDateTime then= OffsetDateTime.parse(odtString)
            
            // TODO: temporal distance check - discard old messages?
            if( Duration.between(then, now).getSeconds() > 10 ) {
                sinkStream.writeUTF("!OK")
            }
            else {
                // Compute mac on message
                byte[] bobResult= bobMac.doFinal(message.getBytes())
                
                // Compare result
                assert aliceResult == bobResult
                
                // Respond OK
                sinkStream.writeUTF("OK")
            }
        }
        finally {
            latch.countDown()
        }
    }
}

def Pipe aliceToBob= Pipe.open()
def Pipe bobToAlice= Pipe.open()
def latch= new CountDownLatch(2)

final Integer dhKeyLength=1024

Thread t1= new Thread(new Alice(dhKeyLength: 1024, 
                                message: "The quick brown fox jumped over the lazy dog", 
                                sinkStream: new DataOutputStream(Channels.newOutputStream(aliceToBob.sink().configureBlocking(true))), 
                                sourceStream: new DataInputStream(Channels.newInputStream(bobToAlice.source().configureBlocking(true))), 
                                latch: latch))
Thread t2= new Thread(new Bob(sinkStream: new DataOutputStream(Channels.newOutputStream(bobToAlice.sink().configureBlocking(true))), 
                                sourceStream: new DataInputStream(Channels.newInputStream(aliceToBob.source().configureBlocking(true))), 
                                latch: latch))
t1.start()
t2.start()

latch.await()
println "done"
