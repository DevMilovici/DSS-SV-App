package key;

import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.DSSASN1Utils;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.x509.KeyStoreCertificateSource;
import eu.europa.esig.dss.utils.Utils;

import java.io.*;
import java.util.Date;
import java.util.List;

/**
 * Class for loading, creating and managing different types of keystores
 */
public class KeyStoreManager {

    private boolean _allowExpired = false;
    private KeyStoreCertificateSource _keyStoreCertificateSource = null;

    public KeyStoreManager() { }

    /**
     * Creates a new KeyStoreCertificateSource
     * @param keyStoreType
     * @param allowExpired
     * @param password
     */
    public void CreateCertificateKeyStore(String keyStoreType, boolean allowExpired, String password)
    {
        _keyStoreCertificateSource = new KeyStoreCertificateSource((InputStream)null, keyStoreType, password);
        _allowExpired = allowExpired;
    }

    /**
     * Adds a certificate to the current certificate store
     * @param certificatePath
     * @throws Exception
     */
    public void AddCertificateToKeyStore(String certificatePath) throws Exception {
        if(_keyStoreCertificateSource == null)
            throw new IllegalStateException("KeyStoreCertificateSource is null! Call CreateCertificateKeyStore() OR OpenCertificateKeyStore() first!");

        try (InputStream is = new FileInputStream(certificatePath))
        {
            CertificateToken cert = DSSUtils.loadCertificate(is);
            if (!_allowExpired && !cert.isValidOn(new Date()))
            {
                throw new IllegalArgumentException(String.format("Certificate %s cannot be added to the keyStore! "
                        + "Renew the certificate or change ALLOW_EXPIRED value to true.", DSSASN1Utils.getSubjectCommonName(cert)));
            }

            _keyStoreCertificateSource.addCertificateToKeyStore(cert);
        }
    }

    /**
     * Saves the current certificate store to a file.
     * @param outputPath
     * @throws Exception
     */
    public void SaveCertificateKeyStore(String outputPath) throws Exception {
        if(_keyStoreCertificateSource == null)
            throw new IllegalStateException("KeyStoreCertificateSource is null! Call CreateCertificateKeyStore() OR OpenCertificateKeyStore() first!");

        OutputStream outputStream = new FileOutputStream(outputPath);

        _keyStoreCertificateSource.store(outputStream);

        Utils.closeQuietly(outputStream);
    }

    /**
     * Opens an existing KeyStoreCertificateSource
     * @param keyStorePath
     * @param keyStoreType
     * @param allowExpired
     * @param password
     * @throws Exception
     */
    public void OpenCertificateKeyStore(String keyStorePath,  String keyStoreType, boolean allowExpired, String password) throws Exception {
        _keyStoreCertificateSource = new KeyStoreCertificateSource(new File(keyStorePath), keyStoreType, password);
        _allowExpired = allowExpired;
    }

    public void SetAllowExpired(boolean allowExpired)
    {
        _allowExpired = allowExpired;
    }

    /**
     * Return all certicates of the current store
     * @return
     */
    public List<CertificateToken> GetKeyStoreCertificates()
    {
        return _keyStoreCertificateSource.getCertificates();
    }
}
