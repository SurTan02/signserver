package com.tugasakhir.signserver.service;


import com.tugasakhir.signserver.dto.SignAttribute;
import com.tugasakhir.signserver.dto.User;
import eu.europa.esig.dss.enumerations.*;
import eu.europa.esig.dss.model.*;
import eu.europa.esig.dss.pades.PAdESSignatureParameters;
import eu.europa.esig.dss.pades.SignatureFieldParameters;
import eu.europa.esig.dss.pades.SignatureImageParameters;
import eu.europa.esig.dss.pades.signature.ExternalCMSService;
import eu.europa.esig.dss.pades.signature.PAdESWithExternalCMSService;
import eu.europa.esig.dss.pdf.IPdfObjFactory;
import eu.europa.esig.dss.pdf.PDFSignatureService;
import eu.europa.esig.dss.pdf.ServiceLoaderPdfObjFactory;
import eu.europa.esig.dss.service.tsp.OnlineTSPSource;
import eu.europa.esig.dss.token.DSSPrivateKeyEntry;
import eu.europa.esig.dss.token.Pkcs12SignatureToken;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.security.KeyStore;
import java.util.List;

@Service
public class PDFSigningService extends SignService<PAdESSignatureParameters>{
    private static final Logger LOG = LoggerFactory.getLogger(PDFSigningService.class);
    private PAdESSignatureParameters parameters;
    public PDFSigningService(StorageService storageService){
        super(storageService, "PADES");
        this.parameters = new PAdESSignatureParameters();
    }
    @Override
    public PAdESSignatureParameters getParams(DSSPrivateKeyEntry entry, User user, SignAttribute signAttribute, DSSDocument toSignDocument){
        try {
            PAdESSignatureParameters pAdESSignatureParameters = new PAdESSignatureParameters();
            pAdESSignatureParameters.setDigestAlgorithm(DigestAlgorithm.SHA256);
            pAdESSignatureParameters.setSignatureLevel(SignatureLevel.PAdES_BASELINE_LT);
            pAdESSignatureParameters.setSigningCertificate(entry.getCertificate());
            pAdESSignatureParameters.setCertificateChain(entry.getCertificateChain());
            pAdESSignatureParameters.setLocation(signAttribute.getLocation());
            pAdESSignatureParameters.setReason(signAttribute.getReason());

            if (signAttribute.getIsVisibleSignature()){
                LOG.info("Sign visible");
                pAdESSignatureParameters.setImageParameters(getVisibleSignature(user, signAttribute, toSignDocument));
            }

            return pAdESSignatureParameters;
        } catch (Exception e){
            LOG.error("PDF Params Error:" + e.getMessage());
            throw e;
        }
    }

    private SignatureImageParameters getVisibleSignature(User user, SignAttribute signAttribute, DSSDocument toSignDocument){
        try {
            DSSDocument imageDSS;
            // If no image file provided for visible signature, retrieve from server
            if (signAttribute.getSignatureImg() == null){
                byte[] img= storageService.getSignatureImage(String.format("%s/%s.png", user.getEmail(), user.getEmail()));
                imageDSS = new InMemoryDocument(img);
            } else {
                imageDSS = new InMemoryDocument(signAttribute.getSignatureImg().getBytes());
            }

            // Initialize visual signature and configure
            SignatureFieldParameters fieldParameters = getSignatureField(signAttribute, toSignDocument);
            SignatureImageParameters imageParameters = new SignatureImageParameters();
            imageParameters.setImage(imageDSS);
            imageParameters.setAlignmentHorizontal(VisualSignatureAlignmentHorizontal.CENTER);
            imageParameters.setAlignmentVertical(VisualSignatureAlignmentVertical.MIDDLE);
            imageParameters.setFieldParameters(fieldParameters);
            return imageParameters;
        } catch (Exception e){
            LOG.error("NO Signature Image Provided, Signing with invisible signature..");
            return null;
        }
    }

    private SignatureFieldParameters getSignatureField(SignAttribute signAttribute, DSSDocument toSignDocument){
        try {
            SignatureFieldParameters fieldParameters = new SignatureFieldParameters();

            IPdfObjFactory pdfObjFactory = new ServiceLoaderPdfObjFactory();
            PDFSignatureService pdfSignatureService = pdfObjFactory.newPAdESSignatureService();
            List<String> preparedFields = pdfSignatureService.getAvailableSignatureFields(toSignDocument);

            if (preparedFields.contains(signAttribute.getSignatureFieldName())){
                LOG.warn(signAttribute.getSignatureFieldName());
                fieldParameters.setFieldId(signAttribute.getSignatureFieldName());
            } else{
                LOG.info("NO Signature field prepared, create a new Signature Filed");
                fieldParameters.setOriginX(signAttribute.getOriginX());
                fieldParameters.setOriginY(signAttribute.getOriginY());
                fieldParameters.setWidth(signAttribute.getWidth());
                fieldParameters.setHeight(signAttribute.getHeight());
            }

            return fieldParameters;
        } catch (Exception e){
            LOG.error("getSignatureField: Failed to get signature field");
            throw e;
        }
    }

    public byte[] signDigest(User user, byte[] document, String hashOfDocument, SignAttribute signAttribute) throws Exception {
        LOG.info("Start sign digest of one digest for " + user.getEmail() + user.getName());
        byte[] userP12 = storageService.getPKCS12File(String.format("%s/%s", user.getEmail(), user.getEmail()));
        try (Pkcs12SignatureToken token = new Pkcs12SignatureToken(userP12, new KeyStore.PasswordProtection(user.getPassphrase().toCharArray()))) {
            DSSDocument toSignDocument = new InMemoryDocument(document);
            DSSPrivateKeyEntry privateKeyEntry = token.getKeys().get(0);

            this.parameters = getParams(privateKeyEntry, user, signAttribute, toSignDocument);

            PAdESWithExternalCMSService service = new PAdESWithExternalCMSService();
            service.setCertificateVerifier(commonCertificateVerifier);
            String tspServer = "https://freetsa.org/tsr";
            OnlineTSPSource onlineTSPSource = new OnlineTSPSource(tspServer);
            service.setTspSource(onlineTSPSource);

            // Prepare the PDF signature revision and compute message-digest of the byte range content
            DSSMessageDigest messageDigest = service.getMessageDigest(toSignDocument, this.parameters);
            DSSDocument cmsSignature = getExternalCMSSignature(user, messageDigest);


            // BATAS SUCI - SESUAI CMD
            DigestDocument digestDocument = new DigestDocument();
            digestDocument.addDigest(DigestAlgorithm.SHA256, toSignDocument.getDigest(DigestAlgorithm.SHA256));
            LOG.info("digest suci {}", digestDocument.getExistingDigest());
            // BATAS SUCI - SESUAI CMD

            DSSDocument signedDocument = service.signDocument(toSignDocument, this.parameters, cmsSignature);

            return signedDocument.openStream().readAllBytes();
        } catch (Exception e) {
            LOG.error("SignDigest Error:" + e.getMessage());
            throw e;
        }
    }

    public DSSDocument getExternalCMSSignature(User user, DSSMessageDigest messageDigest){
        LOG.info("getExternalCMSSignature for " + user.getEmail() + user.getName());
        byte[] userP12 = storageService.getPKCS12File(String.format("%s/%s", user.getEmail(), user.getEmail()));
        try (Pkcs12SignatureToken token = new Pkcs12SignatureToken(userP12, new KeyStore.PasswordProtection(user.getPassphrase().toCharArray()))) {
            DSSPrivateKeyEntry privateKeyEntry = token.getKeys().get(0);

            ExternalCMSService padesCMSGeneratorService = new ExternalCMSService(commonCertificateVerifier);
            PAdESSignatureParameters signatureParameters = new PAdESSignatureParameters();
            signatureParameters.setSigningCertificate(privateKeyEntry.getCertificate());
            signatureParameters.setCertificateChain(privateKeyEntry.getCertificateChain());
            signatureParameters.setSignatureLevel(SignatureLevel.PAdES_BASELINE_B);

            // Create DTBS (data to be signed) using the message-digest of a PDF signature byte range obtained from a client
            ToBeSigned dataToSign = padesCMSGeneratorService.getDataToSign(messageDigest, signatureParameters);
            // Sign the DTBS using a private key connection or remote-signing service
            SignatureValue signatureValue = token.sign(dataToSign, signatureParameters.getDigestAlgorithm(), privateKeyEntry);

            // Create a CMS signature using the provided message-digest, signature parameters and the signature value
            return padesCMSGeneratorService.signMessageDigest(messageDigest, signatureParameters, signatureValue);

        } catch (Exception e) {
            LOG.error("SignDigest Error:" + e.getMessage());
            throw e;
        }
    }
}
