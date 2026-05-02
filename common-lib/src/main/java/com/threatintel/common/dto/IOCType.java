package com.threatintel.common.dto;

/**
 * Enum representing the type of Indicator of Compromise (IOC)
 * Used across all microservices for type safety
 */
public enum IOCType {
    IP,        // IPv4 or IPv6 address
    DOMAIN,    // Domain name (e.g., malicious.com)
    URL,       // Full URL with path
    HASH       // File hash (MD5, SHA1, SHA256)
}