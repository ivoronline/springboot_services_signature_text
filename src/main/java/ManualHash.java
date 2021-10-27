import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.util.Base64;

public class ManualHash {

  //====================================================================================
  // MANUALLY HASH
  //====================================================================================
  public static byte[] hash(String algorithm, byte[] dataBytes) throws Exception {

    //CREATE HASH
    MessageDigest digest    = MessageDigest.getInstance(algorithm);
    byte[]        hashBytes = digest.digest(dataBytes);

    //ENCODE HASH
    byte[]        hashEncoded = Base64.getEncoder().encode(hashBytes);
    String        hashEncodedString = new String(hashEncoded);

    //DISPLAY ENCODED HASH
    System.out.println("HASH      = " + hashEncodedString);

    //RETURN HASH
    return hashBytes;

  }

  //====================================================================================
  // MANUALLY SIGN
  //====================================================================================
  public static byte[] sign(String algorithm, PrivateKey privateKey, byte[] hashBytes) throws Exception {

    //SIGN HASH
    Signature         signature = Signature.getInstance(algorithm);
                      signature.initSign(privateKey);
                      signature.update(hashBytes);
    byte[]            signatureBytes = signature.sign();

    //ENCODE SIGNATURE
    byte[]            signatureEncodedBytes = Base64.getEncoder().encode(signatureBytes);
    String            signatureEncodedString = new String(signatureEncodedBytes);

    //DISPLAY ENCODED HASH & SIGNATURE
    System.out.println("SIGNATURE = " + signatureEncodedString);

    //RETURN SIGNATURE
    return signatureBytes;

  }

  //====================================================================================
  // MANUALLY VERIFY
  //====================================================================================
  public static Boolean verify(String algorithm, PublicKey publicKey, byte[] hashBytes, byte[] signatureBytes) throws Exception {

    //INITIALIZE SIGNATURE
    Signature signature = Signature.getInstance(algorithm);
              signature.initVerify(publicKey);
              signature.update(hashBytes);

    //VERIFY SIGNATURE
    boolean   verified = signature.verify(signatureBytes);

    //DISPLAY VERIFICIATION
    System.out.println("VERIFIED  = " + verified);

    //RETURN SIGNATURE
    return verified;

  }

}
