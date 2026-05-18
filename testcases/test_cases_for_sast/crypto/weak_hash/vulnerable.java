import java.security.MessageDigest;
public class Test {
    public void hash() throws Exception {
        MessageDigest md5 = MessageDigest.getInstance("MD5");
        MessageDigest sha1 = MessageDigest.getInstance("SHA-1");
    }
}
