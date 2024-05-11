package com.tugasakhir.signserver.controllers;

import com.tugasakhir.signserver.dto.SignRequestDTO;
import com.tugasakhir.signserver.dto.SignaturePosition;
import com.tugasakhir.signserver.service.PDFSignService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/sign")
public class SigningController {
    private static final Logger LOG = LoggerFactory.getLogger(PDFSignService.class);
    private final PDFSignService pdfSignService;
    public SigningController(PDFSignService pdfSignService) {
        this.pdfSignService = pdfSignService;
    }
    @PostMapping(value = "/pdf")
    public ResponseEntity<Object> uploadFile(@ModelAttribute SignRequestDTO signRequestDTO) throws Exception {
        try{
            SignaturePosition signaturePosition = new SignaturePosition(
                signRequestDTO.getOriginX(),
                signRequestDTO.getOriginY(),
                signRequestDTO.getWidth(),
                signRequestDTO.getHeight()
            );

            byte[] body = pdfSignService.signDocument(
                signRequestDTO.getEmail(),
                signRequestDTO.getPassphrase(),
                signRequestDTO.getDocument().getBytes(),
                signaturePosition
            );
            return ResponseEntity.accepted().contentType(MediaType.APPLICATION_PDF).body(body);
        } catch (Exception e) {
            LOG.error("Error:" + e.getMessage());
            throw e;
        }

    }
}