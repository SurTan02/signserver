package com.tugasakhir.signserver.dto;

import lombok.Builder;
import lombok.Data;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;

@Data
@Builder
public class SignResponseDTO {
    private String filename;
    private MediaType contentType;
    private byte[] document;
    public ResponseEntity<byte[]> toResponseEntity() {
        HttpHeaders headers = new HttpHeaders();
        headers.add(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"" + this.filename + "\"");

        return ResponseEntity.ok()
                .headers(headers)
                .contentType(this.contentType)
                .body(this.document);
    }
}
