package com.auth.controller;

import com.auth.payload.response.ApiResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.util.Base64;

@RestController
@RequestMapping("/api/files")
@Slf4j
@RequiredArgsConstructor
public class FileToBase64Controller {

    // POST endpoint for converting file to Base64
    @PostMapping("/convertToBase64")
    public ResponseEntity<ApiResponse<String>> convertToBase64(@RequestParam("file") MultipartFile file) {
        try {
            if (file.isEmpty()) {
                log.error("File is empty");
                return ResponseEntity
                        .badRequest()
                        .body(new ApiResponse<>("Error: No file uploaded", null, HttpStatus.BAD_REQUEST.value()));
            }

            // Convert file to Base64 string
            String base64String = encodeFileToBase64(file);

            log.info("File successfully converted to Base64");

            return ResponseEntity.ok(new ApiResponse<>("File successfully converted to Base64", base64String, HttpStatus.OK.value()));
        } catch (IOException e) {
            log.error("Error while processing file", e);
            return ResponseEntity
                    .status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(new ApiResponse<>("Error: Failed to process the file", null, HttpStatus.INTERNAL_SERVER_ERROR.value()));
        }
    }

     // Helper method to encode file to Base64
    private String encodeFileToBase64(MultipartFile file) throws IOException {
        byte[] fileBytes = file.getBytes();
        String encoded = Base64.getEncoder().encodeToString(fileBytes);

        // Regular expression to match any image type prefix (e.g., data:image/png;base64, or data:image/jpeg;base64,)
        String base64PrefixPattern = "data:image/\\w+;base64,";
        if (encoded.matches(base64PrefixPattern)) {
            encoded = encoded.replaceFirst(base64PrefixPattern, "");
        }
        return encoded;
    }
}
