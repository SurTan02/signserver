package com.tugasakhir.signserver.controllers;

import com.tugasakhir.signserver.dto.SignRequestDTO;
import com.tugasakhir.signserver.dto.SignResponseDTO;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.*;
import eu.europa.esig.dss.pades.PAdESSignatureParameters;
import eu.europa.esig.dss.pades.signature.PAdESService;
import eu.europa.esig.dss.token.DSSPrivateKeyEntry;
import eu.europa.esig.dss.token.Pkcs12SignatureToken;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import javax.swing.text.Document;
import java.security.KeyStore;


@RestController
@RequestMapping("/api/sign")
public class SigningController {

    @PostMapping(value = "/pdf", produces = MediaType.APPLICATION_PDF_VALUE)
    public ResponseEntity<Object> uploadFile(@ModelAttribute SignRequestDTO signRequestDTO) {
        try (Pkcs12SignatureToken token = new Pkcs12SignatureToken("", new KeyStore.PasswordProtection("".toCharArray()))){
            DSSDocument toSignDocument = new InMemoryDocument(signRequestDTO.getDocument().getBytes());
            DSSPrivateKeyEntry entry = token.getKeys().get(0);

            PAdESSignatureParameters parameters = new PAdESSignatureParameters();
            parameters.setDigestAlgorithm(DigestAlgorithm.SHA256);
            parameters.setSignatureLevel(SignatureLevel.PAdES_BASELINE_B);
            parameters.setSigningCertificate(entry.getCertificate());
            parameters.setCertificateChain(entry.getCertificateChain());

            CommonCertificateVerifier commonCertificateVerifier = new CommonCertificateVerifier();
            PAdESService service = new PAdESService(commonCertificateVerifier);

            // Get the ToBeSigned data
            ToBeSigned dataToSign = service.getDataToSign(toSignDocument, parameters);

            // Sign the data
            SignatureValue signatureValue = token.sign(dataToSign, parameters.getDigestAlgorithm(), entry);

            // Create the final signed document
            DSSDocument signedDocument = service.signDocument(toSignDocument, parameters, signatureValue);

//            signedDocument.save("testcase/13520059.pdf");

            byte[] body = signedDocument.openStream().readAllBytes();
            return ResponseEntity.accepted().contentType(MediaType.APPLICATION_PDF).body(body);
        } catch (Exception e) {
            e.printStackTrace();
            return ResponseEntity.badRequest().body("Failed");
        }

    }

}