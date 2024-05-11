package com.tugasakhir.signserver.exception;

import com.google.cloud.storage.StorageException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;

import java.util.HashMap;
import java.util.Map;

@ControllerAdvice
public class StorageExceptionHandler {

    @ExceptionHandler(StorageException.class)
    public ResponseEntity<Object> handlerStorageException(){
        Map<String, String> body = new HashMap<>();
        body.put("error", "Failed to retrieve user's file");

        return new ResponseEntity<>(body, HttpStatus.NOT_FOUND);
    }
}
