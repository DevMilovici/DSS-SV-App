package signature;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.token.Pkcs12SignatureToken;
import eu.europa.esig.dss.token.SignatureTokenConnection;
import org.junit.Before;
import org.junit.Test;

import java.io.IOException;
import java.security.KeyStore;

import static org.junit.Assert.assertNotNull;

public class SignatureExecutorTest {

    private SignatureTokenConnection _signatureToken;

    @Before
    public void InitializeComponents() throws Exception {
        // Set the signature token
        _signatureToken = new Pkcs12SignatureToken("src/main/resources/fred_keystore.p12", new KeyStore.PasswordProtection("1234".toCharArray()));
    }

    @Test
    public void TestSignPAdESBaselineB()
    {
        try
        {
            SignatureExecutor signatureExecutor = new SignatureExecutor();

            // Set the file to sign
            signatureExecutor.SetFileToSign("src/main/resources/doc.pdf");
            // Set the format
            signatureExecutor.SetSignatureLevel(SignatureLevel.PAdES_BASELINE_B);
            // Set the signature packaging
            signatureExecutor.SetSignaturePackaging(SignaturePackaging.ENVELOPED);
            // Set the digest algorithm
            signatureExecutor.SetSignatureDigestAlgorithm(DigestAlgorithm.SHA256);

            signatureExecutor.SetSignatureToken(_signatureToken);
            // Set the private key
            signatureExecutor.SetSignaturePrivateKey(0);
            // Sign the document
            signatureExecutor.SignFile();
            // Get the signed document
            DSSDocument signedDocument = signatureExecutor.GetSignedDocument();

            assertNotNull(signedDocument);
        }
        catch (Exception e)
        {
            e.printStackTrace();
        }
    }

    @Test
    public void TestSignCAdES()
    {

    }

    @Test
    public void TestSignXAdES()
    {

    }
}
