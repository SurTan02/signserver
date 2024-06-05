package com.tugasakhir.signserver.service;

import com.tugasakhir.signserver.dto.SignAttribute;
import com.tugasakhir.signserver.dto.User;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.pades.PAdESSignatureParameters;
import eu.europa.esig.dss.pades.SignatureFieldParameters;
import eu.europa.esig.dss.pades.SignatureImageParameters;
import eu.europa.esig.dss.token.DSSPrivateKeyEntry;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.io.IOException;

@Service
public class PDFSigningService extends SignService{
    private final PAdESSignatureParameters parameters;

    private static final Logger LOG = LoggerFactory.getLogger(PDFSigningService.class);

    public PDFSigningService(StorageService storageService){
        super(storageService);
//        this.service = new PAdESService(commonCertificateVerifier);
        this.parameters = new PAdESSignatureParameters();
    }
    @Override
    public PAdESSignatureParameters getParams(DSSPrivateKeyEntry entry, User user, SignAttribute signAttribute) throws IOException {
        try {
//            PAdESSignatureParameters padesParam = new PAdESSignatureParameters();
            this.parameters.setDigestAlgorithm(DigestAlgorithm.SHA256);
            this.parameters.setSignatureLevel(SignatureLevel.PAdES_BASELINE_LT);
            this.parameters.setSigningCertificate(entry.getCertificate());
            this.parameters.setCertificateChain(entry.getCertificateChain());
            LOG.info("PDF" + this.parameters.getSigningCertificate().getCertificate().getSigAlgName());

            if (signAttribute.getIsVisibleSignature()){
                this.parameters.setImageParameters(getVisibleSignature(user, signAttribute));
            }


            return this.parameters;
        } catch (Exception e){
            LOG.error("PDF Params Error:" + e.getMessage());
            throw e;
        }
    }

    public void setSignatureField(){
        try{

        } catch (Exception e){
            LOG.error("PDF Signature Field Error:" + e.getMessage());
            throw e;
        }
    }

    private SignatureImageParameters getVisibleSignature(User user, SignAttribute signAttribute) throws IOException {
        DSSDocument imageDSS;
//        If no image file provided for visible signature, retrieve from server
        if (signAttribute.getSignatureImg() == null){
            byte[] img= storageService.getSignatureImage(String.format("%s/%s.png", user.getEmail(), user.getEmail()));
            imageDSS = new InMemoryDocument(img);
        } else {
            imageDSS = new InMemoryDocument(signAttribute.getSignatureImg().getBytes());
        }
        // Initialize visual signature and configure
        SignatureFieldParameters fieldParameters = getSignatureField(signAttribute);
        SignatureImageParameters imageParameters = new SignatureImageParameters();
        imageParameters.setImage(imageDSS);
        imageParameters.setFieldParameters(fieldParameters);

        return imageParameters;
    }

    private SignatureFieldParameters getSignatureField(SignAttribute signAttribute){
        SignatureFieldParameters fieldParameters = new SignatureFieldParameters();
        fieldParameters.setFieldId("Signature1");

        // the origin is the left and top corner of the page
        fieldParameters.setOriginX(signAttribute.getOriginX());
        fieldParameters.setOriginY(signAttribute.getOriginY());
        fieldParameters.setWidth(signAttribute.getWidth());
        fieldParameters.setHeight(signAttribute.getHeight());

        return fieldParameters;
    }

}
