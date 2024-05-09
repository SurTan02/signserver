package com.tugasakhir.signserver.dto;

import lombok.Builder;
import lombok.Data;
import org.springframework.web.multipart.MultipartFile;

@Data
@Builder
public class SignResponseDTO {
//    private String filename;
    private MultipartFile document;
}
