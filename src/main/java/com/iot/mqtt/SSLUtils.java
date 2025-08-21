package com.iot.mqtt;

import cn.hutool.core.io.FileUtil;
import net.tongsuo.TlcpKeyManagerImpl;
import net.tongsuo.TongsuoProvider;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.net.ssl.*;
import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;

public class SSLUtils {

    private static final String CLIENT_ENC_ALIAS = "CLIENT_ENC_ENTRY";
    private static final String CLIENT_SIGN_ALIAS = "CLIENT_SIGN_ENTRY";
    private static final String CA = "CA";
    private static final String TLCP_KEY_MANAGER_FACTORY = "TlcpKeyManagerFactory";
    private static final String PKCS12 = "PKCS12";
    private static final String PKIX = "PKIX";
    private static final String TLCP = "TLCP";
    private static final String X509 = "X.509";
    private static final String EC = "EC";
    private static final char[] EMPTY_PASSWORD = new char[0];

    public static SSLSocketFactory createSocketFactory(
            final String caCrtFile,
            final String clientEncCrt,
            final String clientEncKey,
            final String clientSignCrt,
            final String clientSignKey) throws Exception {
        X509Certificate caCert = loadX509FromPem(caCrtFile);
        X509Certificate clientSignCert = loadX509FromPem(clientSignCrt);
        X509Certificate clientEncCert = loadX509FromPem(clientEncCrt);
        PrivateKey clientSignPrivateKey = readSM2PrivateKeyPemFile(clientSignKey);
        PrivateKey clientEncPrivateKey = readSM2PrivateKeyPemFile(clientEncKey);

        X509Certificate[] clientSignCertChain = new X509Certificate[]{clientSignCert, caCert};
        X509Certificate[] clientEncCertChain = new X509Certificate[]{clientEncCert, caCert};

        KeyStore ks = KeyStore.getInstance(PKCS12, new BouncyCastleProvider());
        ks.load(null);
        ks.setKeyEntry(CLIENT_ENC_ALIAS, clientEncPrivateKey, EMPTY_PASSWORD, clientEncCertChain);
        ks.setKeyEntry(CLIENT_SIGN_ALIAS, clientSignPrivateKey, EMPTY_PASSWORD, clientSignCertChain);
        ks.setCertificateEntry(CA, caCert);

        KeyManagerFactory kmf = KeyManagerFactory.getInstance(TLCP_KEY_MANAGER_FACTORY, new TongsuoProvider());
        kmf.init(ks, EMPTY_PASSWORD);

        KeyManager[] clientKeyManagers = kmf.getKeyManagers();
        if (clientKeyManagers.length > 0 && clientKeyManagers[0] instanceof TlcpKeyManagerImpl) {
            TlcpKeyManagerImpl tlcpKeyManager = (TlcpKeyManagerImpl) clientKeyManagers[0];
            tlcpKeyManager.setTlcpEncAlias(CLIENT_ENC_ALIAS);
            tlcpKeyManager.setTlcpSignAlias(CLIENT_SIGN_ALIAS);
        }

        kmf.init(ks, EMPTY_PASSWORD);
        kmf.init(ks, EMPTY_PASSWORD);

        KeyManager[] kms = kmf.getKeyManagers();
        boolean hasTlcp = false;
        for (KeyManager km : kms) {
            if (km instanceof TlcpKeyManagerImpl) {
                TlcpKeyManagerImpl tlcp = (TlcpKeyManagerImpl) km;
                tlcp.setTlcpEncAlias(CLIENT_ENC_ALIAS);
                tlcp.setTlcpSignAlias(CLIENT_SIGN_ALIAS);
                hasTlcp = true;
            }
        }
        if (!hasTlcp) {
            throw new IllegalStateException("No TlcpKeyManagerImpl from KeyManagerFactory. Ensure TongsuoProvider is registered and used.");
        }

        TrustManagerFactory tmf = TrustManagerFactory.getInstance(PKIX, new TongsuoProvider());
        tmf.init(ks);
        TrustManager[] tms = new TrustManager[]{new TrustAllManager()};

        SSLContext sslContext = SSLContext.getInstance(TLCP, new TongsuoProvider());
        sslContext.init(kms, tms, new SecureRandom());

        return sslContext.getSocketFactory();
    }

    private static X509Certificate loadX509FromPem(String path) throws Exception {
        try (InputStream in = openFile(path)) {
            CertificateFactory cf = CertificateFactory.getInstance(X509);
            return (X509Certificate) cf.generateCertificate(in);
        }
    }

    public static PrivateKey readSM2PrivateKeyPemFile(String name) throws Exception {
        InputStream inputStream = openFile(name);
        InputStreamReader inputStreamReader = new InputStreamReader(inputStream);
        BufferedReader bufferedReader = new BufferedReader(inputStreamReader);
        StringBuilder sb = new StringBuilder();
        String line = null;
        while ((line = bufferedReader.readLine()) != null) {
            if (line.startsWith("-")) {
                continue;
            }
            sb.append(line).append("\n");
        }
        String ecKey = sb.toString().replaceAll("\\r\\n|\\r|\\n", "");
        Base64.Decoder base64Decoder = Base64.getDecoder();
        byte[] keyByte = base64Decoder.decode(ecKey.getBytes(StandardCharsets.UTF_8));
        PKCS8EncodedKeySpec eks2 = new PKCS8EncodedKeySpec(keyByte);
        KeyFactory keyFactory = KeyFactory.getInstance(EC, new BouncyCastleProvider());
        PrivateKey privateKey = keyFactory.generatePrivate(eks2);
        return privateKey;
    }

    public static InputStream openFile(String name) {
        return FileUtil.getInputStream(name);
    }
}