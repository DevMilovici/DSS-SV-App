package ro.mta.api.sign;

import eu.europa.esig.dss.ws.dto.RemoteDocument;
import eu.europa.esig.dss.ws.dto.SignatureValueDTO;
import eu.europa.esig.dss.ws.server.signing.rest.RestSignatureTokenConnectionImpl;
import eu.europa.esig.dss.ws.server.signing.rest.client.RestSignatureTokenConnection;
import eu.europa.esig.dss.ws.signature.common.RemoteDocumentSignatureServiceImpl;
import eu.europa.esig.dss.ws.signature.dto.parameters.RemoteSignatureParameters;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping(path = "api/sign")
public class SignController {

    private RemoteDocumentSignatureServiceImpl remoteDocumentSignatureService;

    @GetMapping
    public String getSignature() {
        return "Sign Controller";
    }

    @RequestMapping(method = RequestMethod.POST)
    public RemoteDocument sign(RemoteDocument remoteDocument, RemoteSignatureParameters remoteParameters, SignatureValueDTO signatureValueDTO)
    {
        RemoteDocument signedDocument = null;

        try
        {
        }
        catch (Exception exception)
        {
            throw new IllegalStateException(exception.getMessage());
        }

        return signedDocument;
    }
}
