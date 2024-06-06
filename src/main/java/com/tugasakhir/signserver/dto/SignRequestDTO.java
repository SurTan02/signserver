package com.tugasakhir.signserver.dto;

import lombok.Data;
import org.springframework.web.multipart.MultipartFile;

@Data
public class SignRequestDTO {
    private String passphrase;
    private MultipartFile document;

    private SignAttribute signAttribute;
}
