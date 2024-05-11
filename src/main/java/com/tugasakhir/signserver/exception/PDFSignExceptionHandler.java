package com.tugasakhir.signserver.exception;

import eu.europa.esig.dss.model.DSSException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

@ControllerAdvice
public class PDFSignExceptionHandler {

    @ExceptionHandler(DSSException.class)
    public ResponseEntity<Object> handlerStorageException(Exception e){
        Map<String, String> body = new HashMap<>();
        body.put("error", "Failed to Sign document");

        Optional.ofNullable(e.getCause())
                .map(Throwable::getMessage)
                .ifPresent(message -> body.put("error", message));

        return new ResponseEntity<>(body, HttpStatus.NOT_FOUND);
    }
}
