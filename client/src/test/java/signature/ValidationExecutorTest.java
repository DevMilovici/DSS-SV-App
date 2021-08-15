package signature;

import eu.europa.esig.dss.detailedreport.DetailedReport;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.simplereport.SimpleReport;
import org.junit.Before;
import org.junit.Test;

import static org.junit.Assert.assertNotNull;

public class ValidationExecutorTest {
    private ValidationExecutor _validationExecutor;

    @Before
    public void Initialize() {
        _validationExecutor = new ValidationExecutor();
    }

    @Test
    public void ValidatePAdESBaselineB_Test()
    {
        try
        {
            String inputSignedFilePath = "src/main/resources/doc-signedPAdESB.pdf";

            _validationExecutor.SetFileToValidate(inputSignedFilePath);
            //_validationExecutor.AddTrustedCertificateSource("src/main/resources/fred_keystore.p12", "PKCS12", "1234");
            _validationExecutor.AddTrustedCertificate("src/main/resources/certificates/root-ca.crt");
            _validationExecutor.AddTrustedCertificate("src/main/resources/certificates/email-ca.crt");
            _validationExecutor.AddTrustedCertificate("src/main/resources/certificates/fred.crt");
            _validationExecutor.ValidateDocument();

            DiagnosticData diagnosticData = _validationExecutor.GetDiagnosticData();
            String diagnosticDataXML = _validationExecutor.GetDiagnosticDataXML();
            SimpleReport simpleReport = _validationExecutor.GetSimpleReport();
            String simpleReportXML = _validationExecutor.GetSimpleReportXML();
            DetailedReport detailedReport = _validationExecutor.GetDetailedReport();
            String detailedReportXML = _validationExecutor.GetDetailedReportXML();

            assertNotNull(diagnosticData);
            assertNotNull(diagnosticDataXML);
            assertNotNull(simpleReport);
            assertNotNull(simpleReportXML);
            assertNotNull(detailedReport);
            assertNotNull(detailedReportXML);
        }
        catch (Exception exception)
        {
            System.out.println("EXCEPTION from ValidatePAdESBaselineB_Test(): " + exception.getMessage());
        }
    }
}
