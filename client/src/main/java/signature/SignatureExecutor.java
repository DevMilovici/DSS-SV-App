package signature;

import eu.europa.esig.dss.cades.CAdESSignatureParameters;
import eu.europa.esig.dss.cades.signature.CAdESService;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.pades.PAdESSignatureParameters;
import eu.europa.esig.dss.pades.signature.PAdESService;
import eu.europa.esig.dss.service.http.commons.TimestampDataLoader;
import eu.europa.esig.dss.service.tsp.OnlineTSPSource;
import eu.europa.esig.dss.token.DSSPrivateKeyEntry;
import eu.europa.esig.dss.token.SignatureTokenConnection;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import eu.europa.esig.dss.xades.signature.XAdESService;

import java.io.File;
import java.util.List;

/**
 * Class for signing files according to various formats (CAdES, PAdES, XAdES)
 */
public class SignatureExecutor {
    private DSSDocument _documentToSign = null;
    private SignatureLevel _signatureLevel = null;
    private SignaturePackaging _signaturePackaging = null;
    private DigestAlgorithm _digestAlgorithm = null;
    private SignatureTokenConnection _signatureToken = null;
    private DSSPrivateKeyEntry _privateKey = null;
    private OnlineTSPSource _onlineTSPSource = null;

    private DSSDocument _signedDocument = null;

    public SignatureExecutor() { }

    /**
     * Sets the file which is to be signed
     * @param fileToSignPath
     */
    public void SetFileToSign(String fileToSignPath)
    {
        File fileToSign = new File(fileToSignPath);

        _documentToSign = new FileDocument(fileToSign);
    }

    /**
     * Sets the signature format (CAdES, PAdES, XAdES) and level (-B, -T, -LT, -LT, -LTA)
     * @param signatureLevel
     */
    public void SetSignatureLevel(SignatureLevel signatureLevel)
    {
        _signatureLevel = signatureLevel;
    }

    /**
     * Sets the timestamp server url
     * @param tspServerUrl
     */
    public void SetTimestampSource(String tspServerUrl)
    {
        _onlineTSPSource = new OnlineTSPSource(tspServerUrl);
        // Use the specific content-type
        _onlineTSPSource.setDataLoader(new TimestampDataLoader());
    }

    /**
     * Sets the signature packaging method
     *      - DETACHED: The signature is detached from the signed document
     *      - ENVELOPED: The signature is enveloped to the signed document
     *      - ENVELOPING: The signature envelops the signed document
     *      - INTERNALLY_DETACHED: The signature file contains the signed document (XAdES only)
     * @param signaturePackaging
     */
    public void SetSignaturePackaging(SignaturePackaging signaturePackaging)
    {
        _signaturePackaging = signaturePackaging;
    }

    /**
     * Sets the signature digest algorithm
     */
    public void SetSignatureDigestAlgorithm(DigestAlgorithm digestAlgorithm)
    {
        _digestAlgorithm = digestAlgorithm;
    }

    /**
     * Sets the signature token type
     *      - PKCS#11 Signature Token (SmartCard)
     *      - PKCS#12 Signature Token (.p12 file)
     *      - MSCAPI Signature Token (Microsoft SmartCard interface)
     *      - JKS SignatureToken (.jks file)
     */
    public void SetSignatureToken(SignatureTokenConnection signatureToken)
    {
        _signatureToken = signatureToken;
    }

    /**
     * Sets the private key from the signature token which will be used to create the signature
     * @param privateKeyEntryIndex
     * @throws Exception
     */
    public void SetSignaturePrivateKey(int privateKeyEntryIndex) throws Exception {
        try
        {
            List<DSSPrivateKeyEntry> privateKeys = _signatureToken.getKeys();

            _privateKey = privateKeys.get(privateKeyEntryIndex);
        }
        catch (Exception exception)
        {
            throw new Exception("SetSignaturePrivateKey():  " + exception.getMessage());
        }
    }

    /**
     * Prints all available private keys loaded into signature token
     */
    public void PrintPrivateKeys()
    {
        List<DSSPrivateKeyEntry> privateKeys = _signatureToken.getKeys();

        for(int keyIndex = 0; keyIndex < privateKeys.size(); keyIndex++)
        {
            DSSPrivateKeyEntry key = privateKeys.get(keyIndex);
            System.out.println("(" + (keyIndex + 1) + ") " + key.getCertificate().getSubject().getPrincipal() + " - " + key.getCertificate().getIssuer().getPrincipal() + " - " + key.getCertificate().getSerialNumber());
        }
    }

    /**
     * Signs the file set according to the set signature parameters
     * @return
     * @throws Exception
     */
    public void SignFile() throws Exception {
        try
        {
            switch (_signatureLevel)
            {
                case CAdES_BASELINE_B:
                case CAdES_BASELINE_T:
                case CAdES_BASELINE_LT:
                case CAdES_BASELINE_LTA:
                    signCAdES();
                    break;
                case PAdES_BASELINE_B:
                case PAdES_BASELINE_T:
                case PAdES_BASELINE_LT:
                case PAdES_BASELINE_LTA:
                    signPAdES();
                    break;
                case XAdES_BASELINE_B:
                case XAdES_BASELINE_T:
                case XAdES_BASELINE_LT:
                case XAdES_BASELINE_LTA:
                    signXAdES();
                    break;
                default:
                    throw new Exception("unsupported signature level.");
            }
        }
        catch (Exception exception)
        {
            throw new Exception("EXCEPTION from SignFile(): " + exception.getMessage());
        }
    }

    public void ExtendSignature() throws Exception {
        try
        {
            switch (_signatureLevel)
            {
                case CAdES_BASELINE_T:
                case CAdES_BASELINE_LT:
                case CAdES_BASELINE_LTA:
                    extendCAdES();
                    break;
                case PAdES_BASELINE_T:
                case PAdES_BASELINE_LT:
                case PAdES_BASELINE_LTA:
                    extendPAdES();
                    break;
                case XAdES_BASELINE_T:
                case XAdES_BASELINE_LT:
                case XAdES_BASELINE_LTA:
                    extendXAdES();
                    break;
                default:
                    throw new Exception("unsupported signature level.");
            }
        }
        catch (Exception exception)
        {
            throw new Exception("EXCEPTION from SignFile(): " + exception.getMessage());
        }
    }

    /**
     * Returns the signed document
     * @return
     */
    public DSSDocument GetSignedDocument()
    {
        return _signedDocument;
    }


    /**
     * Signs the file in CAdES format
     */
    private void signCAdES()
    {
        // Preparing parameters for the CAdES signature
        CAdESSignatureParameters cadesParameters = new CAdESSignatureParameters();
        // We set the level of the signature (-B, -T, -LT, -LTA).
        cadesParameters.setSignatureLevel(_signatureLevel);
        // We set the type of the signature packaging (ENVELOPING, DETACHED).
        cadesParameters.setSignaturePackaging(_signaturePackaging);
        // We set the digest algorithm to use with the signature algorithm. You must use the
        // same parameter when you invoke the method sign on the token. The default value is SHA256
        cadesParameters.setDigestAlgorithm(_digestAlgorithm);

        // We set the signing certificate
        cadesParameters.setSigningCertificate(_privateKey.getCertificate());
        // We set the certificate chain
        cadesParameters.setCertificateChain(_privateKey.getCertificateChain());

        // Create common certificate verifier
        CommonCertificateVerifier commonCertificateVerifier = new CommonCertificateVerifier();
        // Create CAdESService for signature
        CAdESService cadesService = new CAdESService(commonCertificateVerifier);

        // Sets the timestamp source
        if(_onlineTSPSource != null)
            cadesService.setTspSource(_onlineTSPSource);

        // Get the SignedInfo segment that need to be signed.
        ToBeSigned dataToSign = cadesService.getDataToSign(_documentToSign, cadesParameters);

        // This function obtains the signature value for signed information using the private key and specified algorithm
        SignatureValue signatureValue = _signatureToken.sign(dataToSign, _digestAlgorithm, _privateKey);

        // We invoke the CAdESService to sign the document with the signature value obtained in the previous step.
        _signedDocument = cadesService.signDocument(_documentToSign, cadesParameters, signatureValue);
    }

    private void extendCAdES() {
        // TODO: implement
    }

    /**
     * Signs the file in PAdES format
     */
    private void signPAdES()
    {
        // Preparing parameters for the PAdES signature
        PAdESSignatureParameters padesParameters = new PAdESSignatureParameters();
        // We choose the level of the signature (-B, -T, -LT, -LTA).
        padesParameters.setSignatureLevel(_signatureLevel);
        // We set the digest algorithm to use with the signature algorithm. You must use the
        // same parameter when you invoke the method sign on the token. The default value is SHA256
        padesParameters.setDigestAlgorithm(_digestAlgorithm);

        // We set the signing certificate
        padesParameters.setSigningCertificate(_privateKey.getCertificate());
        // We set the certificate chain
        padesParameters.setCertificateChain(_privateKey.getCertificateChain());

        // Create common certificate verifier
        CommonCertificateVerifier commonCertificateVerifier = new CommonCertificateVerifier();
        // Create PAdESService for signature
        PAdESService padesService = new PAdESService(commonCertificateVerifier);

        // Sets the timestamp source
        if(_onlineTSPSource != null)
            padesService.setTspSource(_onlineTSPSource);

        // Get the SignedInfo segment that is to be signed.
        ToBeSigned dataToSign = padesService.getDataToSign(_documentToSign, padesParameters);

        // This function obtains the signature value for signed information using the private key and the specified digest algorithm
        SignatureValue signatureValue = _signatureToken.sign(dataToSign, _digestAlgorithm, _privateKey);

        // We invoke the padesService to sign the document with the signature value obtained in the previous step.
        _signedDocument = padesService.signDocument(_documentToSign, padesParameters, signatureValue);
    }

    private void extendPAdES()
    {
        // Prepare parameters for the PAdES signature
        PAdESSignatureParameters padesParameters = new PAdESSignatureParameters();

        // Set the signature level (-T, -LT, -LTA)
        padesParameters.setSignatureLevel(_signatureLevel);

        // We set the digest algorithm to use with the signature algorithm. You must use the
        // same parameter when you invoke the method sign on the token. The default value is SHA256
        padesParameters.setDigestAlgorithm(_digestAlgorithm);

        // We set the signing certificate
        padesParameters.setSigningCertificate(_privateKey.getCertificate());

        // We set the certificate chain
        padesParameters.setCertificateChain(_privateKey.getCertificateChain());

        // Create common certificate verifier
        CommonCertificateVerifier commonCertificateVerifier = new CommonCertificateVerifier();

        // Create PAdESService for signature
        PAdESService padesService = new PAdESService(commonCertificateVerifier);

        // Sets the timestamp source
        padesService.setTspSource(_onlineTSPSource);

        // Extend the document signature
        _signedDocument = padesService.extendDocument(_documentToSign, padesParameters);
    }

    /**
     * Signs the file in XAdES format
     */
    private void signXAdES()
    {
        // Instantiate parameters which will pe set for specific XAdES signature
        XAdESSignatureParameters xadesParameters = new XAdESSignatureParameters();
        // We choose the level of the signature (-B, -T, -LT, -LTA).
        xadesParameters.setSignatureLevel(_signatureLevel);
        // We choose the type of the signature packaging (ENVELOPING, DETACHED).
        xadesParameters.setSignaturePackaging(_signaturePackaging);
        // We set the digest algorithm to use with the signature algorithm. You must use the same parameter when you invoke the method sign on the token.
        xadesParameters.setDigestAlgorithm(_digestAlgorithm);
        // We set the signing certificate
        xadesParameters.setSigningCertificate(_privateKey.getCertificate());
        // We set the certificate chain
        xadesParameters.setCertificateChain(_privateKey.getCertificateChain());

        // Create common certificate verifier
        CommonCertificateVerifier commonCertificateVerifier = new CommonCertificateVerifier();
        // Create CAdES xadesService for signature
        XAdESService xadesService = new XAdESService(commonCertificateVerifier);

        // Sets the timestamp source
        if(_onlineTSPSource != null)
            xadesService.setTspSource(_onlineTSPSource);

        // Get the SignedInfo segment that is to be signed.
        ToBeSigned dataToSign = xadesService.getDataToSign(_documentToSign, xadesParameters);

        // This function obtains the signature value for signed information using the private key and specified algorithm
        SignatureValue signatureValue = _signatureToken.sign(dataToSign, _digestAlgorithm, _privateKey);

        // We invoke the xadesService to sign the document with the signature value obtained in the previous step.
        _signedDocument = xadesService.signDocument(_documentToSign, xadesParameters, signatureValue);
    }

    private void extendXAdES() {
        // TODO: implement
    }
}
