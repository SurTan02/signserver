package com.tugasakhir.signserver.service;

import com.tugasakhir.signserver.dto.SignAttribute;
import com.tugasakhir.signserver.dto.User;
import eu.europa.esig.dss.AbstractSignatureParameters;
import eu.europa.esig.dss.cades.CAdESSignatureParameters;
import eu.europa.esig.dss.cades.signature.CAdESService;
import eu.europa.esig.dss.model.*;
import eu.europa.esig.dss.pades.PAdESSignatureParameters;
import eu.europa.esig.dss.pades.signature.PAdESService;
import eu.europa.esig.dss.service.tsp.OnlineTSPSource;
import eu.europa.esig.dss.token.DSSPrivateKeyEntry;
import eu.europa.esig.dss.token.Pkcs12SignatureToken;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.security.KeyStore;
import java.security.SignatureException;
public abstract class SignService<T>{
    private static final Logger LOG = LoggerFactory.getLogger(SignService.class);
    protected final StorageService storageService;

    @SuppressWarnings("rawtypes")
    protected DocumentSignatureService service;
    @SuppressWarnings("rawtypes")
    protected AbstractSignatureParameters parameters;
    protected static final CommonCertificateVerifier commonCertificateVerifier = CommonCertificateVerifierSingleton.getInstance();

    public SignService(StorageService storageService, String signatureType) {
        this.storageService = storageService;

        switch (signatureType){
            case "PADES":
                this.service = new PAdESService(commonCertificateVerifier);
                this.parameters = new PAdESSignatureParameters();
                break;
            case "CADES":
                this.service = new CAdESService(commonCertificateVerifier);
                this.parameters = new CAdESSignatureParameters();
                break;
            default:
                LOG.error("Unknown Signature Type");
        }

        // Set the Timestamp source
        String tspServer = "https://freetsa.org/tsr";
        OnlineTSPSource onlineTSPSource = new OnlineTSPSource(tspServer);
        this.service.setTspSource(onlineTSPSource);
    }

    @SuppressWarnings("unchecked")
    public ToBeSigned getDataToSign(byte[] dataToSign) throws SignatureException {
        LOG.info("Start getDataToSign with one document");
        try {
            DSSDocument toSignDocument = new InMemoryDocument(dataToSign);
            ToBeSigned toBeSigned = service.getDataToSign(toSignDocument, parameters);
            LOG.info("End getDataToSign with one document");
            return toBeSigned;
        } catch (Exception e) {
            LOG.error("getDataToSign Error:" + e.getMessage());
            throw new SignatureException(e.getMessage(), e);
        }
    }

    @SuppressWarnings({"unchecked", "rawtypes"})
    public byte[] signDocument(User user, byte[] document, SignAttribute signAttribute) throws Exception {
        LOG.info("Start signDocument one document for {} {}", user.getEmail(), user.getName());
        byte[] userP12 = storageService.getPKCS12File(String.format("%s/%s", user.getEmail(), user.getEmail()));
        try (Pkcs12SignatureToken token = new Pkcs12SignatureToken(userP12, new KeyStore.PasswordProtection(user.getPassphrase().toCharArray()))) {
            DSSDocument toSignDocument = new InMemoryDocument(document);
            DSSPrivateKeyEntry privateKeyEntry = token.getKeys().get(0);
            this.parameters = (AbstractSignatureParameters) getParams(privateKeyEntry, user, signAttribute, toSignDocument);
            ToBeSigned dataToSign = getDataToSign(document);

            SignatureValue signatureValue = token.sign(dataToSign, this.parameters.getDigestAlgorithm(), privateKeyEntry);
            // Create the final signed document
            DSSDocument signedDocument = service.signDocument(toSignDocument, this.parameters, signatureValue);
            signedDocument.save("test.p7b");
            LOG.info("Finish signDocument with one document {}", signedDocument.getMimeType());
            return signedDocument.openStream().readAllBytes();

        } catch (Exception e) {
            LOG.error("Sign Error:" + e.getMessage());
            throw e;
        }
    }

    public abstract T getParams(DSSPrivateKeyEntry entry, User user, SignAttribute signAttribute, DSSDocument toSignDocument) throws IOException;

}
