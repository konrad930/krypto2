package Krypto;

import java.io.*;
import java.security.*;
import java.security.cert.CertificateException;
import java.util.Random;
import javax.crypto.KeyGenerator;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import javax.crypto.SecretKey;

public class Program {

    public static void main (String[] args)throws Exception {

        // wczytanie hasla
        System.out.println("Podaj haslo : ");
        BufferedReader bufferRead = new BufferedReader(new InputStreamReader(System.in));
        String s = bufferRead.readLine();
        char pass[] = s.toCharArray(); //"konrad"
        Security.addProvider(new BouncyCastleProvider());

        //wczytanie keystora lub utworzenie nowego
        KeyStore ks = loadKeyStore(pass,args[1],args[2]);

        try{
            // pliki
            File f = new File(args[4]);
            File f2 = new File(args[5]);

            if(args[3].equals("-e"))
                new AesCrypt("AES/"+args[0]+"/PKCS5Padding").encrypt(ks.getKey(args[2], pass),f,f2);
            else if(args[3].equals("-d"))
                new AesCrypt("AES/"+args[0]+"/PKCS5Padding").decrypt(ks.getKey(args[2], pass),f,f2);
            else
                System.out.print("Blad argumentu");
        }
        catch(ArrayIndexOutOfBoundsException e){
            System.out.print("Zla liczba argumentow");
        }
        catch(NoSuchAlgorithmException e){
            System.out.print("Zly algorytm");
        }
    }

    public static KeyStore loadKeyStore(char[]pass,String path,String keyId) throws KeyStoreException, CertificateException, NoSuchAlgorithmException, IOException {

        KeyStore ks = KeyStore.getInstance("JCEKS");
        try {
            ks.load(new FileInputStream(path), pass);
        }catch (FileNotFoundException e){
            File file = new File(path);
            ks.load(null,null);
            SecretKey secretKey = KeyGenerator.getInstance("AES").generateKey();

            KeyStore.SecretKeyEntry keyStoreEntry = new KeyStore.SecretKeyEntry(secretKey);
            KeyStore.PasswordProtection keyPassword = new KeyStore.PasswordProtection(pass);

            ks.setEntry(keyId, keyStoreEntry, keyPassword);
            ks.store(new FileOutputStream(file), pass);

            ks.load(new FileInputStream(file), pass);
        } catch (Exception e){}
        return ks;
    }

    public static void challenge(File m0,File m1,KeyStore ks,String keyId,char[]pass,
                                 String algorytm,Mode mode,String path){
        File result = new File(path);
        try {
            if(mode == Mode.Encrypt)
                if(new Random().nextInt(1) == 0)
                    new AesCrypt(algorytm).encrypt(ks.getKey(keyId, pass),m0,result);
                else
                    new AesCrypt(algorytm).encrypt(ks.getKey(keyId, pass),m1,result);
            if(mode == Mode.Decrypt)
                if(new Random().nextInt(1) == 0)
                    new AesCrypt(algorytm).decrypt(ks.getKey(keyId, pass),m0,result);
                else
                    new AesCrypt(algorytm).decrypt(ks.getKey(keyId, pass),m1,result);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
