package com.threatintel.extraction_service.util;

import com.threatintel.common.dto.IOC;
import com.threatintel.common.dto.IOCType;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Slf4j
@Component
public class IOCExtractor {

    // IPv4 pattern - matches valid IP addresses
    private static final Pattern IP_PATTERN =
            Pattern.compile("\\b(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\." +
                    "(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\." +
                    "(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\." +
                    "(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\b");

    // Domain pattern - matches domain names
    private static final Pattern DOMAIN_PATTERN =
            Pattern.compile("\\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\\.)+[a-zA-Z]{2,}\\b");

    // Private IP ranges (exclude these)
    private static final Set<String> PRIVATE_IP_PREFIXES = Set.of(
            "10.", "172.16.", "172.17.", "172.18.", "172.19.", "172.20.",
            "172.21.", "172.22.", "172.23.", "172.24.", "172.25.", "172.26.",
            "172.27.", "172.28.", "172.29.", "172.30.", "172.31.", "192.168.", "127."
    );

    /**
     * Extract all IOCs (IPs and Domains) from raw text
     */
    public List<IOC> extractIOCs(String rawData, String source) {
        List<IOC> iocs = new ArrayList<>();

        if (rawData == null || rawData.isEmpty()) {
            return iocs;
        }

        // Extract IPs
        Set<String> ips = extractIPs(rawData);
        for (String ip : ips) {
            if (isValidPublicIP(ip)) {
                IOC ioc = IOC.builder()
                        .type(IOCType.IP)
                        .value(ip)
                        .source(source)
                        .processedAt(LocalDateTime.now())
                        .validated(true)
                        .build();
                iocs.add(ioc);
                log.debug("Extracted IP: {}", ip);
            }
        }

        // Extract Domains
        Set<String> domains = extractDomains(rawData);
        for (String domain : domains) {
            if (isValidDomain(domain)) {
                IOC ioc = IOC.builder()
                        .type(IOCType.DOMAIN)
                        .value(domain)
                        .source(source)
                        .processedAt(LocalDateTime.now())
                        .validated(true)
                        .build();
                iocs.add(ioc);
                log.debug("Extracted Domain: {}", domain);
            }
        }

        log.info("Extracted {} IOCs from {} data", iocs.size(), source);
        return iocs;
    }

    /**
     * Extract unique IP addresses from text
     */
    private Set<String> extractIPs(String text) {
        Set<String> ips = new HashSet<>();
        Matcher matcher = IP_PATTERN.matcher(text);
        while (matcher.find()) {
            ips.add(matcher.group());
        }
        return ips;
    }

    /**
     * Extract unique domain names from text
     */
    private Set<String> extractDomains(String text) {
        Set<String> domains = new HashSet<>();
        Matcher matcher = DOMAIN_PATTERN.matcher(text);
        while (matcher.find()) {
            String domain = matcher.group().toLowerCase();
            domains.add(domain);
        }
        return domains;
    }

    /**
     * Validate that IP is public (not private/reserved)
     */
    private boolean isValidPublicIP(String ip) {
        // Check if private IP
        for (String prefix : PRIVATE_IP_PREFIXES) {
            if (ip.startsWith(prefix)) {
                log.debug("Skipping private IP: {}", ip);
                return false;
            }
        }

        // Check each octet
        String[] parts = ip.split("\\.");
        for (String part : parts) {
            int num = Integer.parseInt(part);
            if (num < 0 || num > 255) {
                return false;
            }
        }

        return true;
    }

    /**
     * Validate domain name
     */
    private boolean isValidDomain(String domain) {
        // Minimum length check
        if (domain.length() < 4 || domain.length() > 253) {
            return false;
        }

        // Must have at least one dot
        if (!domain.contains(".")) {
            return false;
        }

        // No consecutive dots
        if (domain.contains("..")) {
            return false;
        }

        return true;
    }
}