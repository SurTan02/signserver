package com.tugasakhir.signserver.controllers;

import com.tugasakhir.signserver.dto.SignRequestDTO;
import com.tugasakhir.signserver.dto.User;
import com.tugasakhir.signserver.service.PDFSigningService;
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
    private static final Logger LOG = LoggerFactory.getLogger(SigningController.class);
    private final PDFSigningService pdfSignService;
    public SigningController(PDFSigningService pdfSignService) {
        this.pdfSignService = pdfSignService;
    }
    @PostMapping(value = "/pdf")
    public ResponseEntity<Object> uploadFile(@ModelAttribute SignRequestDTO signRequestDTO) throws Exception {
        try{
//            SignAttribute signAttribute= signRequestDTO.getSignAttribute();
            User user = new User(signRequestDTO.getEmail(), signRequestDTO.getPassphrase(), "Suryanto");
            byte[] body = pdfSignService.signDocument(
                user,
                signRequestDTO.getDocument().getBytes(),
                signRequestDTO.getSignAttribute()
            );
            return ResponseEntity.accepted().contentType(MediaType.APPLICATION_PDF).body(body);
        } catch (Exception e) {
            LOG.error("Error:" + e.getMessage());
            throw e;
        }

    }
}