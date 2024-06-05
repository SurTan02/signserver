package com.tugasakhir.signserver.service;

import eu.europa.esig.dss.service.crl.OnlineCRLSource;
import eu.europa.esig.dss.service.ocsp.OnlineOCSPSource;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;


public class CommonCertificateVerifierSingleton {
    private static CommonCertificateVerifier INSTANCE;
    public static CommonCertificateVerifier getInstance() {
        if (INSTANCE == null){
            INSTANCE = new CommonCertificateVerifier();
            INSTANCE.setCheckRevocationForUntrustedChains(true);
            INSTANCE.setCrlSource(new OnlineCRLSource());
            INSTANCE.setOcspSource(new OnlineOCSPSource());
        }

        return INSTANCE;
    }
}
