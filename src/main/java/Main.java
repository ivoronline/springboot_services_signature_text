import java.nio.charset.StandardCharsets;
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
    byte[]            dataBytes  = dataString.getBytes(StandardCharsets.UTF_8);

    //CREATE KEYS
    KeyPairGenerator  keyPairGenerator = KeyPairGenerator.getInstance("RSA");
                      keyPairGenerator.initialize(2048);
    KeyPair           keyPair    = keyPairGenerator.generateKeyPair();
    PrivateKey        privateKey = keyPair.getPrivate();
    PublicKey         publicKey  = keyPair.getPublic();

    //SIGN
    SHA1withRSA  (privateKey, publicKey, dataBytes);
    SHA256withRSA(privateKey, publicKey, dataBytes);

  }

  //====================================================================================
  // SHA1 WITH RSA
  //====================================================================================
  private static void SHA1withRSA(PrivateKey privateKey, PublicKey publicKey, byte[] dataBytes) throws Exception {

    //LOG
    System.out.println("\nSHA1 WITH RSA ==================================================================");

    //AUTOMATICALLY SIGN & VERIFY
    System.out.println("\nAUTOMATICALLY SIGN & VERIFY");
    byte[]  automaticSignatureBytes = AutomaticHash.sign  ("SHA1withRSA", privateKey, dataBytes);
    Boolean automaticVerified       = AutomaticHash.verify("SHA1withRSA", publicKey , dataBytes, automaticSignatureBytes);

    //MANUALLY SIGN & VERIFY
    System.out.println("\nMANUALLY SIGN & VERIFY");
    byte[]  manualHashBytes         = ManualHash.hash   ("SHA-1", dataBytes);
    byte[]  manualPaddingHashBytes  = ManualHash.padding("SHA-1", manualHashBytes);
    byte[]  manualSignatureBytes    = ManualHash.sign   ("NONEwithRSA", privateKey, manualPaddingHashBytes);
    Boolean manualVerified          = ManualHash.verify ("NONEwithRSA", publicKey , manualPaddingHashBytes, manualSignatureBytes);
  }

  //====================================================================================
  // SHA256 WITH RSA
  //====================================================================================
  private static void SHA256withRSA(PrivateKey privateKey, PublicKey publicKey, byte[] dataBytes) throws Exception {

    //LOG
    System.out.println("\nSHA256 WITH RSA ================================================================");

    //AUTOMATICALLY SIGN & VERIFY
    System.out.println("\nAUTOMATICALLY SIGN & VERIFY");
    byte[]  automaticSignatureBytes = AutomaticHash.sign  ("SHA256withRSA", privateKey, dataBytes);
    Boolean automaticVerified       = AutomaticHash.verify("SHA256withRSA", publicKey , dataBytes, automaticSignatureBytes);

    //MANUALLY SIGN & VERIFY
    System.out.println("\nMANUALLY SIGN & VERIFY");
    byte[]  manualHashBytes         = ManualHash.hash   ("SHA-256", dataBytes);
    byte[]  manualPaddingHashBytes  = ManualHash.padding("SHA-256", manualHashBytes);
    byte[]  manualSignatureBytes    = ManualHash.sign   ("NONEwithRSA", privateKey, manualPaddingHashBytes);
    Boolean manualVerified          = ManualHash.verify ("NONEwithRSA", publicKey , manualPaddingHashBytes, manualSignatureBytes);
  }

}
