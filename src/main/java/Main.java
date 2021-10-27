import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;

public class Main {

  //====================================================================================
  // MAIN
  //====================================================================================
  public static void main(String[] args) throws Exception {

    //CREATE DATA
    String            dataString = "Data to be encrypted";
    byte[]            dataBytes  = dataString.getBytes();

    //CREATE KEYS
    KeyPairGenerator  keyPairGenerator = KeyPairGenerator.getInstance("RSA");
                      keyPairGenerator.initialize(2048);
    KeyPair           keyPair    = keyPairGenerator.generateKeyPair();
    PrivateKey        privateKey = keyPair.getPrivate();
    PublicKey         publicKey  = keyPair.getPublic();

    //AUTOMATICALLY SIGN & VERIFY
    System.out.println("\nAUTOMATICALLY SIGN & VERIFY");
    byte[]  automaticSignatureBytes = AutomaticHash.sign  ("SHA256withRSA", privateKey, dataBytes);
    Boolean automaticVerified       = AutomaticHash.verify("SHA256withRSA", publicKey , dataBytes, automaticSignatureBytes);

    //MANUALLY SIGN & VERIFY
    System.out.println("\nMANUALLY SIGN & VERIFY");
    byte[]  manualHashBytes         = ManualHash.hash  ("SHA-256", dataBytes);
    byte[]  manualSignatureBytes    = ManualHash.sign  ("NONEwithRSA", privateKey, manualHashBytes);
    Boolean manualVerified          = ManualHash.verify("NONEwithRSA", publicKey , manualHashBytes, manualSignatureBytes);

  }

}
