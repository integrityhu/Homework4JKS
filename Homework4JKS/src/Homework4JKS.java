import java.io.BufferedInputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.KeyStore.Entry;
import java.security.KeyStore.Entry.Attribute;
import java.security.KeyStore.PasswordProtection;
import java.security.KeyStore.PrivateKeyEntry;
import java.security.KeyStore.ProtectionParameter;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Enumeration;
import java.util.Set;
import java.util.logging.StreamHandler;
import java.util.stream.StreamSupport;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;

import org.apache.commons.codec.binary.Hex;
import org.apache.commons.io.IOUtils;

/*
 * https://www.digitalocean.com/community/tutorials/java-keytool-essentials-working-with-java-keystores
 * http://docs.oracle.com/javase/7/docs/api/java/security/KeyStore.html
 *
 * http://stackoverflow.com/questions/18889058/programmatically-import-ca-trust-cert-into-existing-keystore-file-without-using
 */
public class Homework4JKS {

    private static final String DEFAULT_PASSWORD = "changeit";
    private KeyManagerFactory mgrFact;
    private TrustManagerFactory trustFact;
    private KeyStore serverStore;
    private KeyStore trustStore;

    private static String getCertFingerPrint(String mdAlg, Certificate cert) throws Exception {
        byte[] encCertInfo = cert.getEncoded();
        MessageDigest md = MessageDigest.getInstance(mdAlg);
        byte[] digest = md.digest(encCertInfo);
        return Hex.encodeHexString(digest);
    }

    public SSLContext createSSLContext() throws Exception {
        // create a context and set up a socket factory
        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(mgrFact.getKeyManagers(), trustFact.getTrustManagers(), null);
        return sslContext;
    }

    public KeyStore getKeyStore(String fileName, String passwd) throws NoSuchAlgorithmException, CertificateException, IOException, KeyStoreException {
        KeyStore store = KeyStore.getInstance("JKS");
        log(fileName + " store info: " + store.getProvider().getInfo());
        store.load(getClass().getResourceAsStream(fileName), passwd.toCharArray());
        return store;
    }

    private void initKeyManagerAndStore(String serverJks, String serverPwd) throws Exception {
        mgrFact = KeyManagerFactory.getInstance("SunX509");
        serverStore = getKeyStore(serverJks, serverPwd);
        mgrFact.init(serverStore, DEFAULT_PASSWORD.toCharArray());
        getServerInfo();
    }

    public void initTrustManagerAndStore(String trustJks, String trustPwd) throws Exception {
        trustFact = TrustManagerFactory.getInstance("SunX509");
        trustStore = getKeyStore(trustJks, trustPwd);
        trustFact.init(trustStore);
        getTrustInfo();
    }

    private void getServerInfo() throws Exception {
        Enumeration<String> serverAliases = serverStore.aliases();
        while (serverAliases.hasMoreElements()) {
            String alias = serverAliases.nextElement();
            ProtectionParameter param = new PasswordProtection(DEFAULT_PASSWORD.toCharArray());

            Entry entry = serverStore.getEntry(alias, param);
            if ((entry != null) && (entry instanceof PrivateKeyEntry)) {
                // log(entry.toString());
                PrivateKeyEntry pkEntry = (PrivateKeyEntry) entry;
                Set<Attribute> attrs = entry.getAttributes();
                for (Attribute a : attrs) {
                    log("server info [" + alias + "]." + a.getName() + " = " + a.getValue());
                }
                Certificate cert = pkEntry.getCertificate();
                if (cert != null) {
                    if (cert instanceof X509Certificate) {
                        X509Certificate x509cert = (X509Certificate) pkEntry.getCertificate();
                        log("server cert [" + alias + "].owner = " + x509cert.getSubjectDN().toString());
                        log("server cert [" + alias + "].issuer = " + x509cert.getIssuerDN().toString());
                        log("server cert [" + alias + "].validity = " + String.valueOf(x509cert.getNotBefore()) + " to " + String.valueOf(x509cert.getNotAfter()));
                    }
                    String algorithm = cert.getPublicKey().getAlgorithm();
                    String format = cert.getPublicKey().getFormat();
                    log("server cert [" + alias + "].fingerprint (SHA1) = " + getCertFingerPrint("SHA1", cert));
                    log("server cert [" + alias + "].algorithm = " + algorithm);
                    log("server cert [" + alias + "].format = " + format);
                } else {
                    log("No certification for alias [" + alias + "]");
                }
            }
        }
    }

    private void getTrustInfo() throws Exception {
        Enumeration<String> trustAliases = trustStore.aliases();
        while (trustAliases.hasMoreElements()) {
            String alias = trustAliases.nextElement();
            log("trusted.jks -> alias " + alias);

            Certificate cert = trustStore.getCertificate(alias);
            if (cert != null) {
                String algorithm = cert.getPublicKey().getAlgorithm();
                String format = cert.getPublicKey().getFormat();
                log("cert [" + alias + "].fingerprint (SHA1) = " + getCertFingerPrint("SHA1", cert));
                log("cert [" + alias + "].algorithm = " + algorithm);
                log("cert [" + alias + "].format = " + format);
            }
        }

    }

    private void savePub(PublicKey pub) throws IOException {
        byte[] key = pub.getEncoded();
        FileOutputStream keyfos = new FileOutputStream("/tmp/tomcat.pub");
        keyfos.write(key);
        keyfos.close();
    }

    private void saveSign(byte[] realSig) throws IOException {
        FileOutputStream sigfos = new FileOutputStream("/tmp/readme.sig");
        sigfos.write(realSig);
        sigfos.close();
    }

    private byte[] readFile(String fileName) throws IOException {
        FileInputStream keyfis = new FileInputStream(fileName);
        byte[] encKey = new byte[keyfis.available()];
        keyfis.read(encKey);

        keyfis.close();
        return encKey;
    }

    private PublicKey getPubKey() throws IOException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException {
        byte[] pub = readFile("/tmp/tomcat.pub");
        X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(pub);
        KeyFactory keyFactory = KeyFactory.getInstance("DSA", "SUN");
        PublicKey pubKey = keyFactory.generatePublic(pubKeySpec);
        return pubKey;
    }

    /*
     * https://docs.oracle.com/javase/tutorial/security/index.html
     * https://docs.oracle.com/javase/tutorial/security/apisign/index.html
     */
    private void veriSign() throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException, IOException, InvalidKeyException, SignatureException {
        PublicKey pubKey = getPubKey();
        byte[] sigToVerify = readFile("/tmp/readme.sig");
        Signature sig = Signature.getInstance("SHA1withDSA", "SUN");
        sig.initVerify(pubKey);
        log("sign pubKey.algorithm = " + pubKey.getAlgorithm());                        
        InputStream datafis = getClass().getResourceAsStream("readme.txt");
        //IOUtils.copy(datafis, System.out);
        datafis.close();
        
        datafis = getClass().getResourceAsStream("readme.txt");
        BufferedInputStream bufin = new BufferedInputStream(datafis);        
        byte[] buffer = new byte[1024];
        int len;
        while (bufin.available() != 0) {
            len = bufin.read(buffer);
            sig.update(buffer, 0, len);
        }

        bufin.close();
        datafis.close();
        boolean verifies = sig.verify(sigToVerify);
        log("signature verifies: " + verifies);
    }

    private void genSign() {
        try {
            ProtectionParameter param = new PasswordProtection(DEFAULT_PASSWORD.toCharArray());
            Entry entry = serverStore.getEntry("tomcat", param);
            if (entry instanceof PrivateKeyEntry) {
                PrivateKeyEntry pkEntry = (PrivateKeyEntry) entry;
                PrivateKey pk = pkEntry.getPrivateKey();
                PublicKey pub = pkEntry.getCertificate().getPublicKey();
                Signature dsa = Signature.getInstance("SHA1withDSA", "SUN");
                dsa.initSign(pk);

                InputStream fis = getClass().getResourceAsStream("readme.txt");
                BufferedInputStream bufin = new BufferedInputStream(fis);
                byte[] buffer = new byte[1024];
                int len;
                while ((len = bufin.read(buffer)) >= 0) {
                    dsa.update(buffer, 0, len);
                }

                bufin.close();

                byte[] realSig = dsa.sign();
                saveSign(realSig);
                savePub(pub);
            }
        } catch (Exception e) {
            log("Caught exception " + e.toString());
        }
    }

    public static void main(String[] args) {
        try {
            Homework4JKS hwJKS = new Homework4JKS();

            hwJKS.initKeyManagerAndStore("server.jks", DEFAULT_PASSWORD);
            hwJKS.initTrustManagerAndStore("trusted.jks", DEFAULT_PASSWORD);

            // SSLContext sslContext = hwJKS.createSSLContext();
            //hwJKS.veriSign();
            
            hwJKS.genSign();
            hwJKS.veriSign();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static void log(String m) {
        System.out.println(m);
    }
}
