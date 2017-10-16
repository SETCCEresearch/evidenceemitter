package com.setcce.evidenceemitter.util;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.URL;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.KeyStoreException;
import java.security.UnrecoverableKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;


import java.security.cert.CertificateException;

/**
 * Created by zelicj on 07/07/2017.
 */
public class KeystoreManagement {

    /**
     * Reads a Java keystore from a file.
     *
     * @param keystoreFile
     *          keystore file to read
     * @param password
     *          password for the keystore file
     * @param keyStoreType
     *          type of keystore, e.g., JKS or PKCS12
     * @return the keystore object
     * @throws KeyStoreException
     *           if the type of KeyStore could not be created
     * @throws IOException
     *           if the keystore could not be loaded
     * @throws NoSuchAlgorithmException
     *           if the algorithm used to check the integrity of the keystore
     *           cannot be found
     * @throws CertificateException
     *           if any of the certificates in the keystore could not be loaded
     */
    public static KeyStore loadKeyStore(final File keystoreFile,
                                        final String password,
                                        final String keyStoreType)
            throws KeyStoreException, IOException, NoSuchAlgorithmException,
            CertificateException {
        if (null == keystoreFile) {
            throw new IllegalArgumentException("KeystoreManagement url may not be null");
        }
        final URI keystoreUri = keystoreFile.toURI();
        final URL keystoreUrl = keystoreUri.toURL();
        final KeyStore keystore = KeyStore.getInstance(keyStoreType);
        InputStream is = null;
        try {
            is = keystoreUrl.openStream();
            keystore.load(is, null == password ? null : password.toCharArray());
        } finally {
            if (null != is) {
                is.close();
            }
        }
        return keystore;
    }

    public static KeyPair getKeyPair(final KeyStore keystore,
                                     final String alias,
                                     final String password) throws UnrecoverableKeyException, NoSuchAlgorithmException, KeyStoreException {
        final Key key = keystore.getKey(alias, password.toCharArray());

        final Certificate cert = keystore.getCertificate(alias);
        final PublicKey publicKey = cert.getPublicKey();

        return new KeyPair(publicKey, (PrivateKey) key);
    }

    public static Certificate getCert(final KeyStore keystore,
                                     final String alias) throws UnrecoverableKeyException, NoSuchAlgorithmException, KeyStoreException {
        return keystore.getCertificate(alias);
    }
}
