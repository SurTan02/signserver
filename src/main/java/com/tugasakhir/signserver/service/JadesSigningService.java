package com.tugasakhir.signserver.service;

import com.tugasakhir.signserver.dto.SignAttribute;
import com.tugasakhir.signserver.dto.User;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.JWSSerializationType;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.jades.JAdESSignatureParameters;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.token.DSSPrivateKeyEntry;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

@Service
public class JadesSigningService extends SignService<JAdESSignatureParameters>{
    private static final Logger LOG = LoggerFactory.getLogger(CadesSigningService.class);

    public JadesSigningService(StorageService storageService){
        super(storageService, "JADES");
    }

    @Override
    public JAdESSignatureParameters getParams(DSSPrivateKeyEntry entry, User user, SignAttribute signAttribute, DSSDocument toSignDocument){
        return this.getParams(entry);
    }

    public JAdESSignatureParameters getParams(DSSPrivateKeyEntry entry){
        try {
            JAdESSignatureParameters jAdESSignatureParameters = new JAdESSignatureParameters();
            jAdESSignatureParameters.setDigestAlgorithm(DigestAlgorithm.SHA256);
            jAdESSignatureParameters.setSignatureLevel(SignatureLevel.JAdES_BASELINE_LT);
            jAdESSignatureParameters.setSigningCertificate(entry.getCertificate());
            jAdESSignatureParameters.setCertificateChain(entry.getCertificateChain());
            jAdESSignatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);
            jAdESSignatureParameters.setJwsSerializationType(JWSSerializationType.FLATTENED_JSON_SERIALIZATION);

            return jAdESSignatureParameters;
        } catch (Exception e){
            LOG.error("Jades getParams Error:" + e.getMessage());
            throw e;
        }
    }
}
