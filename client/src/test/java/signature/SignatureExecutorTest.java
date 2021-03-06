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
    public void SignPAdESBaselineB_Test()
    {
        try
        {
            String inputFilePath = "src/main/resources/doc.pdf";
            String outputFilePath = "src/main/resources/doc-signedPAdESB.pdf";
            SignatureExecutor signatureExecutor = new SignatureExecutor();

            // Set the file to sign
            signatureExecutor.SetFileToSign(inputFilePath);
            // Set the format
            signatureExecutor.SetSignatureLevel(SignatureLevel.PAdES_BASELINE_B);
            // Set the signature packaging
            signatureExecutor.SetSignaturePackaging(SignaturePackaging.ENVELOPED);
            // Set the digest algorithm
            signatureExecutor.SetSignatureDigestAlgorithm(DigestAlgorithm.SHA256);
            // Set the signature token
            signatureExecutor.SetSignatureToken(_signatureToken);
            // Set the private key
            signatureExecutor.SetSignaturePrivateKey(0);
            // Sign the document
            signatureExecutor.SignFile();
            // Get the signed document
            DSSDocument signedDocument = signatureExecutor.GetSignedDocument();

            signedDocument.save(outputFilePath);

            assertNotNull(signedDocument);
        }
        catch (Exception exception)
        {
            exception.printStackTrace();
        }
    }

    @Test
    public void ExtendPAdESBToPAdEST()
    {
        try
        {
            String inputFilePath = "src/main/resources/doc-signedPAdESB.pdf";
            String outputFilePath = "src/main/resources/doc-signedPAdEST.pdf";
            String tspServerUrl = "http://dss.nowina.lu/pki-factory/tsa/good-tsa";

            SignatureExecutor signatureExecutor = new SignatureExecutor();

            // Set the file to extend signature
            signatureExecutor.SetFileToSign(inputFilePath);
            // Set the format
            signatureExecutor.SetSignatureLevel(SignatureLevel.PAdES_BASELINE_T);
            // Set the timestamp server URL
            signatureExecutor.SetTimestampSource(tspServerUrl);
            // Set the signature packaging
            signatureExecutor.SetSignaturePackaging(SignaturePackaging.ENVELOPED);
            // Set the digest algorithm
            signatureExecutor.SetSignatureDigestAlgorithm(DigestAlgorithm.SHA256);
            // Set the signature token
            signatureExecutor.SetSignatureToken(_signatureToken);
            // Set the private key
            signatureExecutor.SetSignaturePrivateKey(0);
            // Extend the document
            signatureExecutor.ExtendSignature();
            // Get the signed (augmented) document
            DSSDocument extendedDocument = signatureExecutor.GetSignedDocument();

            extendedDocument.save(outputFilePath);

        }
        catch (Exception exception)
        {
            exception.printStackTrace();
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
