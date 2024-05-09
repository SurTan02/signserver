package com.tugasakhir.signserver.dto;

import lombok.Data;
import org.springframework.web.multipart.MultipartFile;

@Data
public class SignRequestDTO {
    private String filename;
    private String email;
    private String passphrase;
    private MultipartFile document;
}
