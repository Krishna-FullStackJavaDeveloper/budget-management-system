package com.auth.payload.response;

import lombok.*;

@Getter
@Setter
@Data
@NoArgsConstructor
public class ApiResponse<T> {
    private String message;
    private T data;
    private int statusCode;

    public ApiResponse(String message, T data, int statusCode) {
        this.message = message;
        this.data = data;
        this.statusCode = statusCode; // Default status code
    }
}
