import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.util.Base64;

public class AutomaticHash {

  //====================================================================================
  // AUTOMATICALLY SIGN
  //====================================================================================
  public static byte[] sign(String algorithms, PrivateKey privateKey, byte[] dataBytes) throws Exception {

    //CREATE SIGNATURE (use Hash first)
    Signature         signature = Signature.getInstance(algorithms);
                      signature.initSign(privateKey);
                      signature.update(dataBytes);
    byte[]            signatureBytes = signature.sign();

    //ENCODE SIGNATURE
    byte[]            signatureEncodedBytes  = Base64.getEncoder().encode(signatureBytes);
    String            signatureEncodedString = new String(signatureEncodedBytes);

    //DISPLAY ENCODED SIGNATURE
    System.out.println("SIGNATURE = " + signatureEncodedString);

    //RETURN SIGNATURE
    return signatureBytes;

  }

  //====================================================================================
  // AUTOMATICALLY VERIFY
  //====================================================================================
  public static Boolean verify(String algorithms, PublicKey publicKey, byte[] dataBytes, byte[] signatureBytes) throws Exception {

    //INITIALIZE SIGNATURE
    Signature signature = Signature.getInstance(algorithms);
              signature.initVerify(publicKey);
              signature.update(dataBytes);

    //VERIFY SIGNATURE
    boolean   verified = signature.verify(signatureBytes);

    //DISPLAY VERIFICIATION
    System.out.println("VERIFIED  = " + verified);

    //RETURN SIGNATURE
    return verified;

  }

}
