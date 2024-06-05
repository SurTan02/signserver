package com.tugasakhir.signserver.service;

import com.tugasakhir.signserver.dto.SignAttribute;
import com.tugasakhir.signserver.dto.User;
import eu.europa.esig.dss.AbstractSignatureParameters;
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

public abstract class SignService{
    private static final Logger LOG = LoggerFactory.getLogger(SignService.class);
    protected final StorageService storageService;
    @SuppressWarnings("rawtypes")
    protected DocumentSignatureService service;

    @SuppressWarnings("rawtypes")
    private AbstractSignatureParameters parameters;
    protected static final CommonCertificateVerifier commonCertificateVerifier = CommonCertificateVerifierSingleton.getInstance();

    public SignService(StorageService storageService) {
        this.storageService = storageService;
        this.service = new PAdESService((commonCertificateVerifier));
        this.parameters = new PAdESSignatureParameters();

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
            throw new SignatureException(e.getMessage(), e);
        }
    }

    public Pkcs12SignatureToken getUserToken(byte[] userP12, String passphrase) throws Exception {
        try (Pkcs12SignatureToken token = new Pkcs12SignatureToken(userP12, new KeyStore.PasswordProtection(passphrase.toCharArray()))){
            return token;
        } catch (Exception e) {
            throw new Exception(e.getCause().getMessage());
        }
    }
    @SuppressWarnings("unchecked")
    public byte[] signDocument(User user, byte[] document, SignAttribute signAttribute) throws Exception {
        LOG.info("Start signDocument with one document");
        byte[] userP12 = storageService.getPKCS12File(String.format("%s/%s", user.getEmail(), user.getEmail()));
        try (Pkcs12SignatureToken token = new Pkcs12SignatureToken(userP12, new KeyStore.PasswordProtection(user.getPassphrase().toCharArray()))) {
            DSSDocument toSignDocument = new InMemoryDocument(document);

            // Get p12 file
            DSSPrivateKeyEntry entry = token.getKeys().get(0);
//            setParams(entry, user, signaturePosition);
            parameters = getParams(entry, user, signAttribute);
            // Get the ToBeSigned data
            ToBeSigned dataToSign = getDataToSign(document);
            // Sign the data
            SignatureValue signatureValue = token.sign(dataToSign, this.parameters.getDigestAlgorithm(), entry);
            // Create the final signed document
            DSSDocument signedDocument = service.signDocument(toSignDocument, this.parameters, signatureValue);
            LOG.info("Finish signDocument with one document");
            return signedDocument.openStream().readAllBytes();

        } catch (Exception e) {
            LOG.error("Sign Error:" + e.getMessage());
            throw e;
        }
    }
    public abstract PAdESSignatureParameters getParams(DSSPrivateKeyEntry entry, User user, SignAttribute signAttribute) throws IOException;
}
