package com.tugasakhir.signserver.dto;

import lombok.Data;
import org.springframework.web.multipart.MultipartFile;
import eu.europa.esig.dss.enumerations.SignaturePackaging;

@Data
public class CadesSignRequestDTO {
    private String passphrase;
    private MultipartFile document;
    private SignaturePackaging packaging;
}
