package com.tugasakhir.signserver.controllers;

import com.tugasakhir.signserver.dto.CadesSignRequestDTO;
import com.tugasakhir.signserver.dto.SignRequestDTO;
import com.tugasakhir.signserver.dto.SignResponseDTO;
import com.tugasakhir.signserver.dto.User;
import com.tugasakhir.signserver.service.*;
import eu.europa.esig.dss.validation.reports.Reports;
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
    private final CadesSigningService cadesSigningService;
    private final XadesSigningService xadesSigningService;
    private final JadesSigningService jadesSigningService;

    public SigningController(PDFSigningService pdfSignService, CadesSigningService cadesSigningService, XadesSigningService xadesSigningService, JadesSigningService jadesSigningService) {
        this.pdfSignService = pdfSignService;
        this.cadesSigningService = cadesSigningService;
        this.xadesSigningService = xadesSigningService;
        this.jadesSigningService = jadesSigningService;
    }
    @PostMapping(value = "/pdf")
    @PreAuthorize("hasAuthority('SCOPE_Certificate.Read')")
    public ResponseEntity<byte[]> signDocumentPAdES(@AuthenticationPrincipal Jwt jwt, @ModelAttribute SignRequestDTO signRequestDTO) throws Exception {
        try{
            Object preferred_username = jwt.getClaim("preferred_username");
            Object full_name = jwt.getClaim("name");
            User user = new User((String) preferred_username, (String) full_name, signRequestDTO.getPassphrase());
            byte[] signedDocument = pdfSignService.signDocument(
                user,
                signRequestDTO.getDocument().getBytes(),
                signRequestDTO.getSignAttribute()
            );

            return SignResponseDTO.builder()
                    .filename("signed_" + signRequestDTO.getDocument().getOriginalFilename())
                    .contentType(MediaType.APPLICATION_PDF)
                    .document(signedDocument)
                    .build()
                    .toResponseEntity();
        } catch (Exception e) {
            LOG.error("Error:" + e.getMessage());
            throw e;
        }
    }

    @PostMapping(value = "/cades")
    @PreAuthorize("hasAuthority('SCOPE_Certificate.Read')")
    public ResponseEntity<byte[]> signDocumentCAdES(@AuthenticationPrincipal Jwt jwt, @ModelAttribute CadesSignRequestDTO cadesSignRequestDTO) throws Exception {
        try{
            Object preferred_username = jwt.getClaim("preferred_username");
            Object full_name = jwt.getClaim("name");
            User user = new User((String) preferred_username, (String) full_name, cadesSignRequestDTO.getPassphrase());
            byte[] signedDocument = cadesSigningService.signDocument(
                    user,
                    cadesSignRequestDTO.getDocument().getBytes(),
                    null
            );
            return SignResponseDTO.builder()
                    .filename("signed_" + cadesSignRequestDTO.getDocument().getName() + ".p7m")
                    .contentType(MediaType.APPLICATION_OCTET_STREAM)
                    .document(signedDocument)
                    .build()
                    .toResponseEntity();
        } catch (Exception e) {
            LOG.error("Error:" + e.getMessage());
            throw e;
        }
    }

    @PostMapping(value = "/xades")
    @PreAuthorize("hasAuthority('SCOPE_Certificate.Read')")
    public ResponseEntity<byte[]> signDocumentXAdES(@AuthenticationPrincipal Jwt jwt, @ModelAttribute SignRequestDTO signRequestDTO) throws Exception {
        try{
            Object preferred_username = jwt.getClaim("preferred_username");
            Object full_name = jwt.getClaim("name");
            User user = new User((String) preferred_username, (String) full_name, signRequestDTO.getPassphrase());
            byte[] signedDocument = xadesSigningService.signDocument(
                    user,
                    signRequestDTO.getDocument().getBytes(),
                    signRequestDTO.getSignAttribute()
            );

            return SignResponseDTO.builder()
                    .filename("signed_" + signRequestDTO.getDocument().getOriginalFilename())
                    .contentType(MediaType.TEXT_XML)
                    .document(signedDocument)
                    .build()
                    .toResponseEntity();
        } catch (Exception e) {
            LOG.error("Error:" + e.getMessage());
            throw e;
        }
    }

    @PostMapping(value = "/jades")
    @PreAuthorize("hasAuthority('SCOPE_Certificate.Read')")
    public ResponseEntity<byte[]> signDocumentJAdES(@AuthenticationPrincipal Jwt jwt, @ModelAttribute SignRequestDTO signRequestDTO) throws Exception {
        try{
            Object preferred_username = jwt.getClaim("preferred_username");
            Object full_name = jwt.getClaim("name");
            User user = new User((String) preferred_username, (String) full_name, signRequestDTO.getPassphrase());
            byte[] signedDocument = jadesSigningService.signDocument(
                    user,
                    signRequestDTO.getDocument().getBytes(),
                    signRequestDTO.getSignAttribute()
            );

            return SignResponseDTO.builder()
                    .filename("signed_" + signRequestDTO.getDocument().getOriginalFilename())
                    .contentType(MediaType.APPLICATION_JSON)
                    .document(signedDocument)
                    .build()
                    .toResponseEntity();
        } catch (Exception e) {
            LOG.error("Error:" + e.getMessage());
            throw e;
        }
    }

    @PostMapping(value = "/pdf/digest")
    @PreAuthorize("hasAuthority('SCOPE_Certificate.Read')")
    public ResponseEntity<byte[]> uploadFile(@AuthenticationPrincipal Jwt jwt, @ModelAttribute SignRequestDTO signRequestDTO){
        try{
            Object preferred_username = jwt.getClaim("preferred_username");
            Object full_name = jwt.getClaim("name");
            User user = new User((String) preferred_username, (String) full_name, signRequestDTO.getPassphrase());
            byte[] signedDigest = pdfSignService.signDigestFromClient(
                    user,
                    signRequestDTO.getHash(),
                    signRequestDTO.getSignAttribute()
            );
            return ResponseEntity.ok()
                    .contentType(MediaType.APPLICATION_OCTET_STREAM)
                    .body(signedDigest);
        } catch (Exception e) {
            LOG.error("Error:" + e.getMessage());
            throw e;
        }
    }

    @PostMapping(value = "/validate")
    public ResponseEntity<Object> validate(@ModelAttribute SignRequestDTO signRequestDTO) throws Exception {
        try{
            Reports reports = SignService.validate(signRequestDTO.getDocument().getBytes());
            String simpleReport = reports.getXmlSimpleReport();

            return ResponseEntity.ok()
                    .contentType(MediaType.TEXT_XML)
                    .body(simpleReport);
        } catch (Exception e) {
            LOG.error("Error:" + e.getMessage());
            throw e;
        }
    }

    @PostMapping(value = "/original")
    public ResponseEntity<byte[]> getOriginalDocument(@ModelAttribute SignRequestDTO signRequestDTO) throws Exception {
        try{
            byte[] originalDocument = SignService.getOriginalDocument(signRequestDTO.getDocument().getBytes());

            return SignResponseDTO.builder()
                    .filename("signed")
                    .contentType(MediaType.APPLICATION_OCTET_STREAM)
                    .document(originalDocument)
                    .build()
                    .toResponseEntity();
        } catch (Exception e) {
            LOG.error("Error:" + e.getMessage());
            throw e;
        }
    }
}