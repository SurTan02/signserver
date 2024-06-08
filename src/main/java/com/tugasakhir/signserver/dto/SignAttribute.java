package com.tugasakhir.signserver.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.web.multipart.MultipartFile;
@Data
@AllArgsConstructor
@NoArgsConstructor
public class SignAttribute {
    private String signatureType;
    private MultipartFile signatureImg;
    private Boolean isVisibleSignature;
    private String signatureFieldName;
    private String location;
    private String reason;

    private Integer originX;
    private Integer originY;
    private Integer width;
    private Integer height;
}
