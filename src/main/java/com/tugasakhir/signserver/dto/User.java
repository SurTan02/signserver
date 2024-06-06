package com.tugasakhir.signserver.dto;

import lombok.AllArgsConstructor;
import lombok.Data;


@Data
@AllArgsConstructor
public class User {
    private String email;
    private String name;
    private String passphrase;
}

