package com.tugasakhir.signserver.service;

import com.tugasakhir.signserver.dto.SignaturePosition;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.*;
import eu.europa.esig.dss.pades.PAdESSignatureParameters;
import eu.europa.esig.dss.pades.SignatureFieldParameters;
import eu.europa.esig.dss.pades.SignatureImageParameters;
import eu.europa.esig.dss.pades.signature.PAdESService;
import eu.europa.esig.dss.pdf.ServiceLoaderPdfObjFactory;
import eu.europa.esig.dss.token.DSSPrivateKeyEntry;
import eu.europa.esig.dss.token.Pkcs12SignatureToken;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.security.KeyStore;
@Service
public class PDFSignService {
    private static final Logger LOG = LoggerFactory.getLogger(PDFSignService.class);
    private final StorageService storageService;

    public PDFSignService(StorageService storageService) {
        this.storageService = storageService;
    }

    public byte[] signDocument(String email, String passphrase, byte[] document, SignaturePosition signaturePosition) throws Exception {
        LOG.info("Start signDocument with one document");
        byte[] userP12 = storageService.getPKCS12File(email);
        try (Pkcs12SignatureToken token = new Pkcs12SignatureToken(userP12, new KeyStore.PasswordProtection(passphrase.toCharArray()))) {
            // Get p12 file
            DSSPrivateKeyEntry entry = token.getKeys().get(0);
            DSSDocument toSignDocument = new InMemoryDocument(document);

            // Init PaDEs Service
            PAdESSignatureParameters parameters = getParams(entry, email, signaturePosition);

            CommonCertificateVerifier commonCertificateVerifier = new CommonCertificateVerifier();
            PAdESService service = new PAdESService(commonCertificateVerifier);
            service.setPdfObjFactory(new ServiceLoaderPdfObjFactory());
            // Get the ToBeSigned data
            ToBeSigned dataToSign = service.getDataToSign(toSignDocument, parameters);
            // Sign the data
            SignatureValue signatureValue = token.sign(dataToSign, parameters.getDigestAlgorithm(), entry);

            // Create the final signed document
            DSSDocument signedDocument = service.signDocument(toSignDocument, parameters, signatureValue);
            LOG.info("Finish signDocument with one document");
            return signedDocument.openStream().readAllBytes();

        } catch (Exception e) {
            e.printStackTrace();
            LOG.error("Sign Error:" + e.getMessage());
            throw e;
        }
    }

    public PAdESSignatureParameters getParams(DSSPrivateKeyEntry entry, String email, SignaturePosition signaturePosition) throws Exception{
        try {
            PAdESSignatureParameters parameters = new PAdESSignatureParameters();
            parameters.setDigestAlgorithm(DigestAlgorithm.SHA256);
            parameters.setSignatureLevel(SignatureLevel.PAdES_BASELINE_B);
            parameters.setSigningCertificate(entry.getCertificate());
            parameters.setCertificateChain(entry.getCertificateChain());

            // Initialize visual signature and configure
            SignatureImageParameters imageParameters = new SignatureImageParameters();
            byte[] img= storageService.getSignatureImage(email + ".png");
            DSSDocument imageDSS= new InMemoryDocument(img);
            imageParameters.setImage(imageDSS);

            // initialize signature field parameters
            SignatureFieldParameters fieldParameters = new SignatureFieldParameters();
            imageParameters.setFieldParameters(fieldParameters);
            // the origin is the left and top corner of the page
            fieldParameters.setOriginX(signaturePosition.getOriginX());
            fieldParameters.setOriginY(signaturePosition.getOriginY());
            fieldParameters.setWidth(signaturePosition.getWidth());
            fieldParameters.setHeight(signaturePosition.getHeight());
            parameters.setImageParameters(imageParameters);

            return parameters;
        } catch (Exception e){
            LOG.error("PDF Params Error:" + e.getMessage());
            throw e;
        }
    }


}
