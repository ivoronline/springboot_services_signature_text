import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.util.Base64;

public class ManualHash {

  //====================================================================================
  // HASH
  //====================================================================================
  public static byte[] hash(String algorithm, byte[] dataBytes) throws Exception {

    //CREATE HASH
    MessageDigest digest    = MessageDigest.getInstance(algorithm);
    byte[]        hashBytes = digest.digest(dataBytes);

    //DISPLAY ENCODED HASH
    System.out.println("HASH      = " + Base64.getEncoder().encodeToString(hashBytes));

    //RETURN HASH
    return hashBytes;

  }

  //====================================================================================
  // PADDING
  //====================================================================================
  public static byte[] padding(String algorithm, byte[] hashBytes) throws Exception {

    //PREPARE PADDING
    byte[] padding = null;
    if (algorithm.equals("SHA-1"  )) { padding = new byte[] { 0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, (byte) 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14                         }; }
    if (algorithm.equals("SHA-256")) { padding = new byte[] { 0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, (byte) 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20 }; }

    //ADD PADDING & HASH TO RESULTING ARRAY
    byte[] paddingHash = new byte[padding.length + hashBytes.length];
    System.arraycopy(padding  , 0, paddingHash, 0             , padding.length  );
    System.arraycopy(hashBytes, 0, paddingHash, padding.length, hashBytes.length);

    //RETURN HASH
    return paddingHash;

  }

  //====================================================================================
  // SIGN
  //====================================================================================
  public static byte[] sign(String algorithm, PrivateKey privateKey, byte[] paddingHash) throws Exception {

    //SIGN PADDED HASH
    Signature         signature = Signature.getInstance(algorithm);
                      signature.initSign(privateKey);
                      signature.update(paddingHash);
    byte[]            signatureBytes = signature.sign();

    //DISPLAY ENCODED HASH & SIGNATURE
    System.out.println("SIGNATURE = " + Base64.getEncoder().encodeToString(signatureBytes));

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

    //DISPLAY VERIFICATION
    System.out.println("VERIFIED  = " + verified);

    //RETURN SIGNATURE
    return verified;

  }

}
