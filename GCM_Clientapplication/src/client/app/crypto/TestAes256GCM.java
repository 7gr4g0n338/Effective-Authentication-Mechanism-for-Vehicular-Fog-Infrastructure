package client.app.crypto;

public class TestAes256GCM {

    public static void main(String[] args) {
            //Generate and dump KEY so we could use again
            //System.out.println(AesGcm256.toHex(AesGcm256.NewKey()));

            //Generate and dump IV so we could use again
            //System.out.println(AesGcm256.toHex(AesGcm256.NewIv()));

            //Console.ReadKey();

            //using above code these key and iv was generated
            String hexKey = "2192B39425BBD08B6E8E61C5D1F1BC9F428FC569FBC6F78C0BC48FCCDB0F42AE";
            String hexIV = "E1E592E87225847C11D948684F3B070D";

            String plainText = "Test encryption and decryption";
            System.out.println("Plain Text: " + plainText);

            //encrypt - result base64 encoded string
            String encryptedText = AesGcm256.encrypt
                    (plainText, AesGcm256.HexToByte(hexKey), AesGcm256.HexToByte(hexIV));
            System.out.println("Encrypted base64 encoded: " + encryptedText);

            //decrypt - result plain string
            String decryptedText = AesGcm256.decrypt
                    (encryptedText, AesGcm256.HexToByte(hexKey), AesGcm256.HexToByte(hexIV));
            System.out.println("Kz" +AesGcm256.HexToByte(hexKey));
            System.out.println("nonce" +AesGcm256.HexToByte(hexIV));
            System.out.println("Decrypted Text: " + decryptedText);

            if (plainText.equals(decryptedText))
            {
                System.out.println("Test Passed");
            }
            else
            {
                System.out.println("Test Failed");
            }

            /* Console Output
            Plain Text: Test encryption and decryption
            Encrypted base64 encoded: 
                   A/boAixWJKflKviHp2cfDl6l/xn1qw2MsHcKFkrOfm2XOVmawIFct4fS1w7wKw==
            Decrypted Text: Test encryption and decryption
            Test Passed
            Press any key to continue . . .
            */
    }    
}