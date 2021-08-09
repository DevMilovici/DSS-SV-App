import com.google.gson.Gson;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.token.Pkcs12SignatureToken;
import eu.europa.esig.dss.token.SignatureTokenConnection;
import eu.europa.esig.dss.ws.converter.RemoteDocumentConverter;
import eu.europa.esig.dss.ws.dto.RemoteDocument;
import eu.europa.esig.dss.ws.validation.dto.DataToValidateDTO;

import java.io.BufferedReader;
import java.io.File;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.Buffer;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;

public class App {
    public static void main(String[] args)
    {

    }

    // TODO: remove
    public static void sendValidateRequestToApi()
    {
        try
        {
            // Get signed document
            RemoteDocument signedDocument = RemoteDocumentConverter.toRemoteDocument(new FileDocument("src/main/resources/doc-signed.pdf"));
            // Get original document
            RemoteDocument originalDocument = RemoteDocumentConverter.toRemoteDocument(new FileDocument("src/main/resources/doc.pdf"));
            RemoteDocument policy = null;

            DataToValidateDTO dataToValidateDTO = new DataToValidateDTO(signedDocument, originalDocument, policy);

            URL url = new URL("http://localhost:8081/api/validate");
            HttpURLConnection connection = (HttpURLConnection)url.openConnection();
            connection.setRequestMethod("POST");
            connection.setRequestProperty("Content-Type", "application/json; utf-8");
            connection.setRequestProperty("Accept", "application/json");
            connection.setDoOutput(true);
            String jsonInputString = dataToValidateDTO.toString();
            Gson gson = new Gson();
            jsonInputString = gson.toJson(dataToValidateDTO);

            try(OutputStream os = connection.getOutputStream()){
                byte[] input = jsonInputString.getBytes(StandardCharsets.UTF_8);
                os.write(input, 0, input.length);
            }

            try(BufferedReader br = new BufferedReader(
                    new InputStreamReader(connection.getInputStream(), "utf-8"))){
                StringBuilder response = new StringBuilder();
                String responseLine = null;
                while((responseLine = br.readLine()) != null) {
                    response.append(responseLine.trim());
                }

                System.out.println(response.toString());
            }
        }
        catch (Exception exception)
        {
            System.out.println("ERROR: " + exception.getMessage());
        }
    }
}
