package com.tugasakhir.signserver.dto;

import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor
public class SignaturePosition {
    private Integer originX;
    private Integer originY;
    private Integer width;
    private Integer height;
}
