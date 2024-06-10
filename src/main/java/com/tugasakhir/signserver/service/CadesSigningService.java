package com.tugasakhir.signserver.service;

import com.tugasakhir.signserver.dto.SignAttribute;
import com.tugasakhir.signserver.dto.User;
import eu.europa.esig.dss.cades.CAdESSignatureParameters;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.token.DSSPrivateKeyEntry;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

@Service
public class CadesSigningService extends SignService<CAdESSignatureParameters>{
    private static final Logger LOG = LoggerFactory.getLogger(CadesSigningService.class);

    public CadesSigningService(StorageService storageService){
        super(storageService, "CADES");
    }

    @Override
    public CAdESSignatureParameters getParams(DSSPrivateKeyEntry entry, User user, SignAttribute signAttribute, DSSDocument toSignDocument){
        return this.getCadesParameters(entry);
    }

    public CAdESSignatureParameters getCadesParameters(DSSPrivateKeyEntry entry){
        try {
            CAdESSignatureParameters cAdESSignatureParameters = new CAdESSignatureParameters();
            cAdESSignatureParameters.setDigestAlgorithm(DigestAlgorithm.SHA256);
            cAdESSignatureParameters.setSignatureLevel(SignatureLevel.CAdES_BASELINE_LT);
            cAdESSignatureParameters.setSigningCertificate(entry.getCertificate());
            cAdESSignatureParameters.setCertificateChain(entry.getCertificateChain());
            cAdESSignatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);


            return cAdESSignatureParameters;
        } catch (Exception e){
            LOG.error("Cades Params Error:" + e.getMessage());
            throw e;
        }
    }
}
