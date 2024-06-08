package com.tugasakhir.signserver.service;

import com.tugasakhir.signserver.dto.SignAttribute;
import com.tugasakhir.signserver.dto.User;
import eu.europa.esig.dss.AbstractSignatureParameters;
import eu.europa.esig.dss.cades.CAdESSignatureParameters;
import eu.europa.esig.dss.cades.signature.CAdESService;
import eu.europa.esig.dss.enumerations.*;
import eu.europa.esig.dss.model.*;
import eu.europa.esig.dss.pades.PAdESSignatureParameters;
import eu.europa.esig.dss.pades.signature.PAdESService;
import eu.europa.esig.dss.pades.signature.PAdESWithExternalCMSService;
import eu.europa.esig.dss.pdf.IPdfObjFactory;
import eu.europa.esig.dss.pdf.PDFSignatureService;
import eu.europa.esig.dss.pdf.ServiceLoaderPdfObjFactory;
import eu.europa.esig.dss.service.tsp.OnlineTSPSource;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.token.DSSPrivateKeyEntry;
import eu.europa.esig.dss.token.Pkcs12SignatureToken;
import eu.europa.esig.dss.validation.AdvancedSignature;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.security.KeyStore;
import java.security.MessageDigest;
import java.util.List;

@Service
public class CadesSigningService extends SignService<CAdESSignatureParameters>{
    private static final Logger LOG = LoggerFactory.getLogger(CadesSigningService.class);
    private final CAdESService service;

    public CadesSigningService(StorageService storageService){
        super(storageService, "CADES");
        this.service = new CAdESService(commonCertificateVerifier);
        CAdESSignatureParameters parameters = new CAdESSignatureParameters();

        String tspServer = "https://freetsa.org/tsr";
        OnlineTSPSource onlineTSPSource = new OnlineTSPSource(tspServer);
        this.service.setTspSource(onlineTSPSource);
    }
    @Override
    public CAdESSignatureParameters getParams(DSSPrivateKeyEntry entry, User user, SignAttribute signAttribute, DSSDocument toSignDocument){
        try {
            CAdESSignatureParameters cAdESSignatureParameters = new CAdESSignatureParameters();
            cAdESSignatureParameters.setDigestAlgorithm(DigestAlgorithm.SHA256);
            cAdESSignatureParameters.setSignatureLevel(SignatureLevel.CAdES_BASELINE_LT);
            cAdESSignatureParameters.setSigningCertificate(entry.getCertificate());
            cAdESSignatureParameters.setCertificateChain(entry.getCertificateChain());
            cAdESSignatureParameters.setSignaturePackaging(SignaturePackaging.DETACHED);


            return cAdESSignatureParameters;
        } catch (Exception e){
            LOG.error("Cades Params Error:" + e.getMessage());
            throw e;
        }
    }
    @Override
    public byte[] signDocument(User user, byte[] document, SignAttribute signAttribute) throws Exception {
        LOG.info("Start sign CADES? one document for {} {}", user.getEmail(), user.getName());
        byte[] userP12 = storageService.getPKCS12File(String.format("%s/%s", user.getEmail(), user.getEmail()));
        try (Pkcs12SignatureToken token = new Pkcs12SignatureToken(userP12, new KeyStore.PasswordProtection(user.getPassphrase().toCharArray()))) {
            DSSDocument toSignDocument = new InMemoryDocument(document);
            DSSPrivateKeyEntry privateKeyEntry = token.getKeys().get(0);
            this.parameters = getParams(privateKeyEntry, user, signAttribute, toSignDocument);
            ToBeSigned dataToSign = getDataToSign(document);

            SignatureValue signatureValue = token.sign(dataToSign, this.parameters.getDigestAlgorithm(), privateKeyEntry);
            // Create the final signed document
            DSSDocument signedDocument = service.signDocument(toSignDocument, (CAdESSignatureParameters) this.parameters, signatureValue);
            signedDocument.save("test.p7b");
            LOG.info("Finish signDocument with one document {}", signedDocument.getMimeType());

// We create an instance of DocumentValidator. DSS automatically selects the validator depending on the
// signature file
            DSSDocument verifiedDocument = new FileDocument("test.p7b");

            SignedDocumentValidator documentValidator = SignedDocumentValidator.fromDocument(verifiedDocument);

    // We set a certificate verifier. It handles the certificate pool, allows to check the certificate status,...
            documentValidator.setCertificateVerifier(commonCertificateVerifier);

    // We retrieve the found signatures
                List<AdvancedSignature> signatures = documentValidator.getSignatures();

    // We select the wanted signature (the first one in our current case)
                AdvancedSignature advancedSignature = signatures.get(0);

    // We call get original document with the related signature id (DSS unique ID)
                List<DSSDocument> originalDocuments = documentValidator.getOriginalDocuments(advancedSignature.getId());

    // We can have one or more original documents depending on the signature (ASiC, PDF,...)
                DSSDocument original = originalDocuments.get(0);

    // Save the extracted original document if needed
                original.save("test.png");

            return signedDocument.openStream().readAllBytes();

        } catch (Exception e) {
            LOG.error("Sign Error:" + e.getMessage());
            throw e;
        }
    }
}
