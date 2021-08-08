package ro.mta.api.validate;

import eu.europa.esig.dss.exception.IllegalInputException;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.policy.ValidationPolicy;
import eu.europa.esig.dss.policy.ValidationPolicyFacade;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.CertificateVerifier;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.dss.ws.converter.RemoteDocumentConverter;
import eu.europa.esig.dss.ws.dto.RemoteDocument;
import eu.europa.esig.dss.ws.validation.common.RemoteDocumentValidationService;
import eu.europa.esig.dss.ws.validation.dto.DataToValidateDTO;
import eu.europa.esig.dss.ws.validation.dto.WSReportsDTO;
import eu.europa.esig.dss.ws.validation.rest.RestDocumentValidationServiceImpl;
import eu.europa.esig.dss.ws.validation.rest.client.RestDocumentValidationService;
import org.springframework.web.bind.annotation.*;

import java.io.ByteArrayInputStream;

@RestController
@RequestMapping(path = "api/validate")
public class ValidationController {

    private CertificateVerifier certificateVerifier;

    @RequestMapping(method = RequestMethod.POST)
    public WSReportsDTO validateDocument(@RequestBody DataToValidateDTO dataToValidateDTO)
    {
        WSReportsDTO reportsDTO = null;

        try
        {
            RemoteDocumentValidationService validationService = new RemoteDocumentValidationService();
            validationService.setVerifier(new CommonCertificateVerifier());

            reportsDTO = validationService.validateDocument(dataToValidateDTO);
        }
        catch (Exception exception)
        {
            System.out.println(exception.getMessage());
        }


        return reportsDTO;
    }


}
