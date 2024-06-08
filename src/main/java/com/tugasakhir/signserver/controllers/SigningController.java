package com.tugasakhir.signserver.controllers;

import com.tugasakhir.signserver.dto.SignRequestDTO;
import com.tugasakhir.signserver.dto.User;
import com.tugasakhir.signserver.service.CadesSigningService;
import com.tugasakhir.signserver.service.PDFSigningService;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.ByteArrayResource;
import org.springframework.http.HttpHeaders;
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
    private final CadesSigningService cadesSigningService;

    public SigningController(PDFSigningService pdfSignService, CadesSigningService cadesSigningService) {
        this.pdfSignService = pdfSignService;
        this.cadesSigningService = cadesSigningService;
    }
    @PostMapping(value = "/pdf")
    @PreAuthorize("hasAuthority('SCOPE_Certificate.Read')")
    public ResponseEntity<Object> signDocumentPAdES(@AuthenticationPrincipal Jwt jwt, @ModelAttribute SignRequestDTO signRequestDTO) throws Exception {
        try{
            Object preferred_username = jwt.getClaim("preferred_username");
            Object full_name = jwt.getClaim("name");
            User user = new User((String) preferred_username, (String) full_name, signRequestDTO.getPassphrase());
            byte[] signedDocument = pdfSignService.signDocument(
                user,
                signRequestDTO.getDocument().getBytes(),
                signRequestDTO.getSignAttribute()
            );
            LOG.info("mime pkcs7 {}", signedDocument);
            return ResponseEntity.accepted().contentType(MediaType.APPLICATION_PDF).body(signedDocument);
        } catch (Exception e) {
            LOG.error("Error:" + e.getMessage());
            throw e;
        }
    }

    @PostMapping(value = "/cades")
    @PreAuthorize("hasAuthority('SCOPE_Certificate.Read')")
    public ResponseEntity<Object> signDocumentCAdES(@AuthenticationPrincipal Jwt jwt, @ModelAttribute SignRequestDTO signRequestDTO) throws Exception {
        try{
            Object preferred_username = jwt.getClaim("preferred_username");
            Object full_name = jwt.getClaim("name");
            User user = new User((String) preferred_username, (String) full_name, signRequestDTO.getPassphrase());
            byte[] signedDocument = cadesSigningService.signDocument(
                    user,
                    signRequestDTO.getDocument().getBytes(),
                    signRequestDTO.getSignAttribute()
            );
//            return ResponseEntity.accepted().contentType(MediaType.).body(signedDocument);
            DSSDocument pkcs7 = new InMemoryDocument(signedDocument);
            byte[] resource = pkcs7.openStream().readAllBytes();

            LOG.info("mime pkcs7 {}", pkcs7.getMimeType());

            HttpHeaders headers = new HttpHeaders();
            headers.add(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=signedDocument.p7s");
            headers.setContentType(MediaType.APPLICATION_OCTET_STREAM);

            return ResponseEntity.ok()
                    .headers(headers)
                    .contentLength(signedDocument.length)
                    .body(resource);
        } catch (Exception e) {
            LOG.error("Error:" + e.getMessage());
            throw e;
        }
    }

    @PostMapping(value = "/pdf/free")
    public ResponseEntity<Object> uploadFile(@ModelAttribute SignRequestDTO signRequestDTO) throws Exception {
        try{
            User user = new User("13520059@mahasiswa.itb.ac.id", "Suryanto", "superadmin");
            byte[] body = pdfSignService.signDigest(
                    user,
                    signRequestDTO.getDocument().getBytes(),
                    signRequestDTO.getHash(),
                    signRequestDTO.getSignAttribute()
            );
            return ResponseEntity.accepted().contentType(MediaType.APPLICATION_PDF).body(body);
        } catch (Exception e) {
            LOG.error("Error:" + e.getMessage());
            throw e;
        }
    }
}