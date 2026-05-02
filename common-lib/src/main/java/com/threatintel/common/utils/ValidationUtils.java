package com.threatintel.common.utils;

import java.util.regex.Pattern;
import java.util.Arrays;
import java.util.List;
import com.threatintel.common.dto.*;

/**
 * Utility class for validating IOC values
 * Used by ExtractionService and ProcessingService
 */
public class ValidationUtils {

    // Regex pattern for valid IPv4 addresses
    // Matches: 192.168.1.1, 8.8.8.8, etc.
    // Does NOT match: 999.999.999.999, 256.1.1.1
    private static final Pattern IP_PATTERN =
            Pattern.compile("^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\." +
                    "(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\." +
                    "(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\." +
                    "(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$");

    // Regex pattern for valid domain names
    // Matches: google.com, sub.domain.co.uk
    private static final Pattern DOMAIN_PATTERN =
            Pattern.compile("^(?!-)[A-Za-z0-9-]{1,63}(?<!-)\\.(?:[A-Za-z0-9-]{1,63}\\.)*[A-Za-z]{2,}$");

    // Private IP ranges (should be lower severity)
    private static final List<String> PRIVATE_IP_RANGES = Arrays.asList(
            "10.",       // 10.0.0.0/8
            "172.16.",   // 172.16.0.0/12
            "172.17.",   // 172.16.0.0/12
            "172.18.",   // 172.16.0.0/12
            "172.19.",   // 172.16.0.0/12
            "172.20.",   // 172.16.0.0/12
            "172.21.",   // 172.16.0.0/12
            "172.22.",   // 172.16.0.0/12
            "172.23.",   // 172.16.0.0/12
            "172.24.",   // 172.16.0.0/12
            "172.25.",   // 172.16.0.0/12
            "172.26.",   // 172.16.0.0/12
            "172.27.",   // 172.16.0.0/12
            "172.28.",   // 172.16.0.0/12
            "172.29.",   // 172.16.0.0/12
            "172.30.",   // 172.16.0.0/12
            "172.31.",   // 172.16.0.0/12
            "192.168.",  // 192.168.0.0/16
            "127."       // Loopback
    );

    // Suspicious TLDs (should get higher severity)
    private static final List<String> SUSPICIOUS_TLDS = Arrays.asList(
            ".xyz", ".top", ".tk", ".ml", ".cf", ".ga", ".gq"
    );

    /**
     * Validates if a string is a proper IPv4 address
     * @param ip The IP address to validate
     * @return true if valid IP, false otherwise
     */
    public static boolean isValidIP(String ip) {
        if (ip == null || ip.isEmpty()) {
            return false;
        }
        return IP_PATTERN.matcher(ip).matches();
    }

    /**
     * Validates if a string is a proper domain name
     * @param domain The domain to validate
     * @return true if valid domain, false otherwise
     */
    public static boolean isValidDomain(String domain) {
        if (domain == null || domain.isEmpty()) {
            return false;
        }
        return DOMAIN_PATTERN.matcher(domain).matches();
    }

    /**
     * Checks if an IP is in private range (internal network)
     * @param ip The IP address to check
     * @return true if private IP, false otherwise
     */
    public static boolean isPrivateIP(String ip) {
        if (ip == null) return false;
        for (String range : PRIVATE_IP_RANGES) {
            if (ip.startsWith(range)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Checks if a domain has a suspicious TLD
     * @param domain The domain to check
     * @return true if suspicious TLD, false otherwise
     */
    public static boolean isSuspiciousTLD(String domain) {
        if (domain == null) return false;
        for (String tld : SUSPICIOUS_TLDS) {
            if (domain.endsWith(tld)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Calculate initial severity score based on IOC characteristics
     * @param type Type of IOC (IP or DOMAIN)
     * @param value The IOC value
     * @return Severity score from 1-10
     */
    public static int calculateInitialSeverity(IOCType type, String value) {
        int score = 5; // Start with medium severity

        if (type == IOCType.IP) {
            if (isPrivateIP(value)) {
                score = 2;  // Private IPs are less severe
            } else {
                score = 6;  // Public IPs are more concerning
            }
        } else if (type == IOCType.DOMAIN) {
            if (isSuspiciousTLD(value)) {
                score = 8;  // Suspicious TLDs are high risk
            } else {
                score = 5;  // Normal domains start medium
            }
        }

        return Math.min(10, Math.max(1, score)); // Clamp between 1-10
    }
}