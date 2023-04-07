public class App 
{
    public static void main(String[] args) 
    {
       SHA256 sha256 = new SHA256();

       sha256.setString("First Java project! (Just a activffwe...ff..F)");
       sha256.compile();

       String hash = sha256.getHash();
       System.out.println(hash);
    }
}