package com.tugasakhir.signserver.service;

import com.tugasakhir.signserver.dto.SignAttribute;
import com.tugasakhir.signserver.dto.User;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.token.DSSPrivateKeyEntry;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

@Service
public class XadesSigningService extends SignService<XAdESSignatureParameters>{
    private static final Logger LOG = LoggerFactory.getLogger(CadesSigningService.class);

    public XadesSigningService(StorageService storageService){
        super(storageService, "XADES");
    }

    @Override
    public XAdESSignatureParameters getParams(DSSPrivateKeyEntry entry, User user, SignAttribute signAttribute, DSSDocument toSignDocument){
        return this.getXadesParameters(entry);
    }

    public XAdESSignatureParameters getXadesParameters(DSSPrivateKeyEntry entry){
        try {
            XAdESSignatureParameters xAdESSignatureParameters = new XAdESSignatureParameters();
            xAdESSignatureParameters.setDigestAlgorithm(DigestAlgorithm.SHA256);
            xAdESSignatureParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_LT);
            xAdESSignatureParameters.setSigningCertificate(entry.getCertificate());
            xAdESSignatureParameters.setCertificateChain(entry.getCertificateChain());
            xAdESSignatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPED);
            xAdESSignatureParameters.setPrettyPrint(true);

            return xAdESSignatureParameters;
        } catch (Exception e){
            LOG.error("XAdES Params Error:" + e.getMessage());
            throw e;
        }
    }
}
