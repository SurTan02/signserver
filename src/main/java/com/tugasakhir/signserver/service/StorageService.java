package com.tugasakhir.signserver.service;

import com.google.cloud.storage.Storage;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;


@Service
public class StorageService {
    private final Storage storage;

    @Value("${bucket.name}")
    private String bucketName;

    public StorageService(Storage storage) {
        this.storage = storage;
    }

    public byte[] getPKCS12File(String fileName) {
        if (!fileName.endsWith(".p12")){
            fileName = fileName + ".p12";
        }

        return storage.readAllBytes(bucketName, fileName);
    }


    public byte[] getSignatureImage(String fileName){
        return storage.readAllBytes(bucketName, fileName);
    }

}
