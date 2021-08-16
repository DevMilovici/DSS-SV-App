package signature;

import eu.europa.esig.dss.detailedreport.DetailedReport;
import eu.europa.esig.dss.detailedreport.DetailedReportFacade;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.DiagnosticDataFacade;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.service.SecureRandomNonceSource;
import eu.europa.esig.dss.service.crl.OnlineCRLSource;
import eu.europa.esig.dss.service.http.commons.CommonsDataLoader;
import eu.europa.esig.dss.service.http.commons.OCSPDataLoader;
import eu.europa.esig.dss.service.ocsp.OnlineOCSPSource;
import eu.europa.esig.dss.simplereport.SimpleReport;
import eu.europa.esig.dss.simplereport.SimpleReportFacade;
import eu.europa.esig.dss.spi.client.http.Protocol;
import eu.europa.esig.dss.spi.x509.CertificateSource;
import eu.europa.esig.dss.spi.x509.CommonCertificateSource;
import eu.europa.esig.dss.spi.x509.CommonTrustedCertificateSource;
import eu.europa.esig.dss.spi.x509.KeyStoreCertificateSource;
import eu.europa.esig.dss.validation.CertificateVerifier;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;

import java.io.File;
import java.io.FileInputStream;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

/**
 * Class for validating different types of signatures.
 */
public class ValidationExecutor {
    private DSSDocument _fileToValidate = null;
    private CertificateVerifier _certificateVerifier;

    private OnlineOCSPSource _onlineOCSPSource = null;
    private OCSPDataLoader _ocspDataLoader = null;

    private OnlineCRLSource _onlineCRLSource = null;
    private CommonsDataLoader _crlDataLoader = null;

    private SignedDocumentValidator _signedDocumentValidator = null;
    private Reports _validationReports = null;

    public ValidationExecutor() {
        _certificateVerifier = new CommonCertificateVerifier();
    }

    /**
     * Sets the file which is to be subject to the signature validation process
     * @param fileToValidatePath Path of the file to validate
     */
    public void SetFileToValidate(String fileToValidatePath) {
        File fileToValidate = new File(fileToValidatePath);

        _fileToValidate = new FileDocument(fileToValidate);
    }

    /**
     * Activate the capability to send OCSP requests
     */
    public void ActivateOCSPCapability() {
        _onlineOCSPSource = new OnlineOCSPSource();

        // Allows setting an implementation of `DataLoader` interface,  processing a querying of
        // a remote revocation server. `CommonsDataLoader` instance is used by default
        _ocspDataLoader = new OCSPDataLoader();
        _onlineOCSPSource.setDataLoader(_ocspDataLoader);

        // TODO: parameterize
        // Defines an arbitrary integer used in OCSP source querying in order to prevent a replay attack.
        // Default : null (not used by default).
        _onlineOCSPSource.setNonceSource(new SecureRandomNonceSource());

        // TODO: parameterize
        // Defines a DigestAlgorithm being used to generate a CertificateID in order to complete an OCSP request.
        // OCSP servers supporting multiple hash functions may produce a revocation response
        // with a digest algorithm depending on the provided CertificateID's algorithm.
        // Default : SHA1 (as a mandatory requirement to be implemented by OCSP servers. See RFC 5019).
        _onlineOCSPSource.setCertIDDigestAlgorithm(DigestAlgorithm.SHA1);

        // Sets the capability to request OCSP Responders
        _certificateVerifier.setOcspSource(_onlineOCSPSource);
    }

    /**
     * Activate the capability to download CRLs
     */
    public void ActivateCRLCapability() {
        _onlineCRLSource = new OnlineCRLSource();

        // Allows setting an implementation of `DataLoader` interface,  processing a querying
        // of a remote revocation server. `CommonsDataLoader` instance is used by default.
        _crlDataLoader = new CommonsDataLoader();
        _onlineCRLSource.setDataLoader(_crlDataLoader);

        // TODO: parameterize
        // Sets a preferred protocol that will be used for obtaining a CRL.
        // E.g. for a list of urls with protocols HTTP, LDAP and FTP, with a defined preferred protocol
        // as FTP, the FTP url will be called first, and in case of an unsuccessful result other url calls
        // will follow.
        // Default: null (urls will be called in a provided order)
        _onlineCRLSource.setPreferredProtocol(Protocol.FTP);

        // Sets the capability to download CRLs
        _certificateVerifier.setCrlSource(_onlineCRLSource);
    }

    // TODO: See addAdjunctCertSources() for _certificateVerifier
    /**
     * Adds certificates which are trusted for the validation process
     * @param certificateKeyStoreSourcePath e.g.: chain.p12
     * @param keyStoreSourceType e.g.: "PKCS12"
     * @param keyStorePassword Password of the key store
     */
    public void AddTrustedCertificateSource(String certificateKeyStoreSourcePath, String keyStoreSourceType, String keyStorePassword) throws Exception {
        try
        {
            CommonTrustedCertificateSource trustedCertificateSource = new CommonTrustedCertificateSource();

            CertificateSource certificateSource =
                    new KeyStoreCertificateSource(new File(certificateKeyStoreSourcePath), keyStoreSourceType, keyStorePassword);

            // Import the keystore as trusted
            trustedCertificateSource.importAsTrusted(certificateSource);

            // Add trust anchors (trusted list, keystore,...) to a list of trusted certificate sources
            // Hint : use method {@code CertificateVerifier.setTrustedCertSources(certSources)} in order to overwrite the existing list
            _certificateVerifier.addTrustedCertSources(trustedCertificateSource);
        }
        catch (Exception exception)
        {
            throw new Exception("EXCEPTION from AddTrustedCertificateSource(): " + exception.getMessage());
        }
    }

    /**
     * Adds trusted anchor
     * @param certificatePath
     */
    public void AddTrustedCertificate(String certificatePath) {

        try
        {
            CommonCertificateSource commonCertificateSource = new CommonCertificateSource();
            CommonTrustedCertificateSource trustedCertificateSource = new CommonTrustedCertificateSource();

            CertificateFactory certificateFactory = CertificateFactory.getInstance("X509");
            File certificateFile = new File(certificatePath);
            FileInputStream certificateFileInputStream = new FileInputStream(certificateFile);
            X509Certificate certificate = (X509Certificate)certificateFactory.generateCertificate(certificateFileInputStream);

            CertificateToken certificateToken = new CertificateToken(certificate);
            commonCertificateSource.addCertificate(certificateToken);

            trustedCertificateSource.importAsTrusted(commonCertificateSource);

            _certificateVerifier.addTrustedCertSources(trustedCertificateSource);
        }
        catch (Exception exception)
        {
            System.out.println("EXCEPTION from AddTrustedCertificate(): " + exception.getMessage());
        }
    }

    /**
     * Adds missing certificates which may be missing
     * @param certificatePath
     */
    public void AddAdjacentCertificate(String certificatePath) {

        try
        {
            CommonCertificateSource commonCertificateSource = new CommonCertificateSource();

            CertificateFactory certificateFactory = CertificateFactory.getInstance("X509");
            File certificateFile = new File(certificatePath);
            FileInputStream certificateFileInputStream = new FileInputStream(certificateFile);
            X509Certificate certificate = (X509Certificate)certificateFactory.generateCertificate(certificateFileInputStream);
            CertificateToken certificateToken = new CertificateToken(certificate);

            commonCertificateSource.addCertificate(certificateToken);

            _certificateVerifier.addAdjunctCertSources(commonCertificateSource);
        }
        catch (Exception exception)
        {
            System.out.println("EXCEPTION from AddTrustedCertificate(): " + exception.getMessage());
        }
    }

    public void ValidateDocument()
    {
        // We create an instance of DocumentValidator
        // It will automatically select the supported validator from the classpath
        _signedDocumentValidator = SignedDocumentValidator.fromDocument(_fileToValidate);

        // We add the certificate verifier (which allows to verify and trust certificates)
        _signedDocumentValidator.setCertificateVerifier(_certificateVerifier);

        // TODO: add possibility to insert a custom validation policy
        // Here, everything is ready. We can execute the validation
        // (for the example, we use the default and embedded validation policy)
        // Executes the validation process and produces validation reports:
        //  Simple report, Detailed report, Diagnostic data and ETSI Validation Report (if enabled)
        _validationReports = _signedDocumentValidator.validateDocument();
    }

    public DiagnosticData GetDiagnosticData()
    {
        return _validationReports.getDiagnosticData();
    }

    public String GetDiagnosticDataXML() throws Exception {
        String result;
        DiagnosticDataFacade diagnosticDataFacade = DiagnosticDataFacade.newFacade();
        try
        {
            result = diagnosticDataFacade.marshall(_validationReports.getDiagnosticDataJaxb());
        }
        catch (Exception exception)
        {
            throw new Exception("EXCEPTION from GetDiagnosticDataXML(): " + exception.getMessage());
        }

        return result;
    }

    public SimpleReport GetSimpleReport()
    {
        // The simple report is a summary of the detailed report (more user-friendly)
        return _validationReports.getSimpleReport();
    }

    public String GetSimpleReportXML() throws Exception {
        String result;

        try
        {
            SimpleReportFacade simpleReportFacade = SimpleReportFacade.newFacade();
            result = simpleReportFacade.marshall(_validationReports.getSimpleReportJaxb());
        }
        catch (Exception exception)
        {
            throw new Exception("EXCEPTION from GetSimpleReportXML(): " + exception.getMessage());
        }

        return result;
    }

    public DetailedReport GetDetailedReport()
    {
        // The detailed report is the result of the process of the diagnostic data and the validation policy
        return _validationReports.getDetailedReport();
    }

    public String GetDetailedReportXML() throws Exception {
        String result;

        try
        {
            DetailedReportFacade detailedReportFacade = DetailedReportFacade.newFacade();
            result = detailedReportFacade.marshall(_validationReports.getDetailedReportJaxb());
        }
        catch (Exception exception)
        {
            throw new Exception("EXCEPTION from GetDetailedReportXML(): " + exception.getMessage());
        }

        return result;
    }
}
