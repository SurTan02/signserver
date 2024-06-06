package com.tugasakhir.signserver.controllers;

import com.tugasakhir.signserver.dto.SignRequestDTO;
import com.tugasakhir.signserver.dto.User;
import com.tugasakhir.signserver.service.PDFSigningService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
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
    @PreAuthorize("hasAuthority('SCOPE_Certificate.Read')")
    public ResponseEntity<Object> signPDF(@AuthenticationPrincipal Jwt jwt, @ModelAttribute SignRequestDTO signRequestDTO) throws Exception {
        try{
            Object preferred_username = jwt.getClaim("preferred_username");
            Object full_name = jwt.getClaim("name");
            User user = new User((String) preferred_username, (String) full_name, signRequestDTO.getPassphrase());
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

    @PostMapping(value = "/pdf/free")
    public ResponseEntity<Object> uploadFile(@AuthenticationPrincipal Jwt jwt, @ModelAttribute SignRequestDTO signRequestDTO) {
        try{
          Object username = jwt.getClaims();
            return ResponseEntity.accepted().contentType(MediaType.APPLICATION_JSON).body(username);
        } catch (Exception e) {
            LOG.error("Error:" + e.getMessage());
            throw e;
        }
    }
}