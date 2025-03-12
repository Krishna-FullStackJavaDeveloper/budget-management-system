package com.auth.globalUtils;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.time.ZoneId;
import java.util.Date;

public class DateFormatUtil {
    public static String formatDate(LocalDateTime dateTime) {
        // Define the custom date-time pattern
        DateTimeFormatter formatter = DateTimeFormatter.ofPattern("dd-MM-yyyy, EEEE | h:mm a");

        // Convert LocalDateTime to desired format string
        return dateTime.format(formatter);
    }

    public static void main(String[] args) {
        // Example date
        LocalDateTime createdAt = LocalDateTime.of(2025, 3, 12, 14, 56, 5, 642487000); // Example datetime

        // Format the date using the method
        String formattedDate = formatDate(createdAt);

        System.out.println(formattedDate); // Output: 12-03-2025, Wednesday | 2:56 PM
    }
}
