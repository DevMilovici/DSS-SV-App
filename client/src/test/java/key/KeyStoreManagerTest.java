package key;

import eu.europa.esig.dss.model.x509.CertificateToken;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import java.util.List;

public class KeyStoreManagerTest {

    KeyStoreManager _keyStoreManager = null;

    @Before
    public void Initialize()
    {
        _keyStoreManager = new KeyStoreManager();
    }

    @Test
    public void PKCS12CreateNewKeyStoreAndSaveAsFile_Test()
    {
        try
        {
            String keyStoreType = "PKCS12";
            boolean keyStoreAllowExpired = false;
            String keyStorePassword = "1234";
            String keyStorePath = "target/advanced.p12";

            _keyStoreManager.CreateCertificateKeyStore(keyStoreType, keyStoreAllowExpired, keyStorePassword);

            _keyStoreManager.AddCertificateToKeyStore("src/main/resources/certificates/root-ca.crt");
            _keyStoreManager.AddCertificateToKeyStore("src/main/resources/certificates/email-ca.crt");
            _keyStoreManager.AddCertificateToKeyStore("src/main/resources/certificates/tls-ca.crt");
            _keyStoreManager.AddCertificateToKeyStore("src/main/resources/certificates/software-ca.crt");
            _keyStoreManager.AddCertificateToKeyStore("src/main/resources/certificates/barney.crt");
            _keyStoreManager.AddCertificateToKeyStore("src/main/resources/certificates/fred.crt");
            _keyStoreManager.AddCertificateToKeyStore("src/main/resources/certificates/green.no.crt");
            _keyStoreManager.AddCertificateToKeyStore("src/main/resources/certificates/software.crt");
            _keyStoreManager.AddCertificateToKeyStore("src/main/resources/certificates/tom.crt");

            List<CertificateToken> certificates = _keyStoreManager.GetKeyStoreCertificates();

            Assert.assertEquals(9, certificates.size());

            _keyStoreManager.SaveCertificateKeyStore("target/advanced.p12");

            KeyStoreManager keyStoreManager2 = new KeyStoreManager();
            keyStoreManager2.OpenCertificateKeyStore(keyStorePath, keyStoreType, keyStoreAllowExpired, keyStorePassword);

            List<CertificateToken> certificates2 = keyStoreManager2.GetKeyStoreCertificates();

            Assert.assertEquals(certificates.size(), certificates2.size());
        }
        catch (Exception exception)
        {
            System.out.println("ERROR: " + exception.getMessage());
        }
    }

    @Test
    public void PKCS12OpenExistentKeyStoreAddNewCertificatesAndSaveAsFile_Test()
    {
        try
        {
            String keyStoreType = "PKCS12";
            boolean keyStoreAllowExpired = false;
            String keyStorePassword = "1234";
            String keyStoreInputPath = "target/advanced.p12";
            String keyStoreOutputPath = "target/advanced2.p12";

            _keyStoreManager.OpenCertificateKeyStore(keyStoreInputPath, keyStoreType, keyStoreAllowExpired, keyStorePassword);
            _keyStoreManager.AddCertificateToKeyStore("src/main/resources/certificates/simple.org.crt");

            List<CertificateToken> certificates = _keyStoreManager.GetKeyStoreCertificates();
            Assert.assertEquals(10, certificates.size());

            KeyStoreManager keyStoreManager2 = new KeyStoreManager();
            keyStoreManager2.OpenCertificateKeyStore(keyStoreOutputPath, keyStoreType, keyStoreAllowExpired, keyStorePassword);

            List<CertificateToken> certificates2 = keyStoreManager2.GetKeyStoreCertificates();

            Assert.assertEquals(certificates.size(), certificates2.size());
        }
        catch (Exception exception)
        {
            System.out.println("ERROR: " + exception.getMessage());
        }
    }
}
