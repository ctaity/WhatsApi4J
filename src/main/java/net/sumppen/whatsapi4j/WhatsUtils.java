package net.sumppen.whatsapi4j;

import org.apache.commons.codec.binary.Base64;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * Created by taity on 6/20/15.
 */
public class WhatsUtils {

    private static byte[] hash_file(String string, File file, boolean b) throws NoSuchAlgorithmException, IOException {
        MessageDigest md;

        md = MessageDigest.getInstance("SHA-256");
        FileInputStream fis = new FileInputStream(file);

        try {
            byte[] dataBytes = new byte[1024];

            int nread = 0;
            while ((nread = fis.read(dataBytes)) != -1) {
                md.update(dataBytes, 0, nread);
            }
            ;
            byte[] mdbytes = md.digest();
            return mdbytes;
        } finally {
            fis.close();
        }
    }

    public static String base64_encode(byte[] data) {
        byte[] enc = Base64.encodeBase64(data);
        return new String(enc);
    }

    public static String b64hash(File file) throws IOException, NoSuchAlgorithmException {
        return base64_encode(hash_file("sha256", file, true));
    }

    public static String getJID(String number) {
        if (!number.contains("@")) {
            //check if group message
            if (number.contains("-")) {
                //to group
                number = number + "@" + WhatsApi.WHATSAPP_GROUP_SERVER;
            } else {
                //to normal user
                number = number + "@" + WhatsApi.WHATSAPP_SERVER;
            }
        }

        return number;
    }

}