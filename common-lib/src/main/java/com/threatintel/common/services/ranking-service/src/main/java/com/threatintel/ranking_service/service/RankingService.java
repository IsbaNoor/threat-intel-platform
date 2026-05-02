package com.threatintel.ranking_service.service;

import com.threatintel.common.dto.IOC;
import com.threatintel.common.dto.IOCType;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.kafka.annotation.KafkaListener;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.Arrays;
import java.util.List;

@Slf4j
@Service
@RequiredArgsConstructor
public class RankingService {

    private final KafkaTemplate<String, IOC> kafkaTemplate;

    // Suspicious TLDs get higher score
    private static final List<String> SUSPICIOUS_TLDS = Arrays.asList(
            ".xyz", ".top", ".tk", ".ml", ".cf", ".ga", ".gq", ".cc"
    );

    // Known bad IP prefixes (example - you can expand)
    private static final List<String> SUSPICIOUS_IP_PREFIXES = Arrays.asList(
            "185.130", "45.33", "103.45", "185.230"
    );

    @KafkaListener(topics = "validated-iocs", groupId = "ranking-group")
    public void rankIOC(IOC ioc) {
        log.info("⭐ Ranking: {} = {}", ioc.getType(), ioc.getValue());

        // Calculate severity score (1-10, 10 is most dangerous)
        int score = calculateSeverity(ioc);

        // Determine confidence level
        String confidence = getConfidence(score);

        // Get threat categories
        List<String> categories = getCategories(ioc, score);

        // Set the ranking details
        ioc.setSeverityScore(score);
        ioc.setConfidence(confidence);
        ioc.setCategories(categories);
        ioc.setRankingSource("FALLBACK"); // Using fallback since no external API
        ioc.setProcessedAt(LocalDateTime.now());

        // Send to next topic
        kafkaTemplate.send("ranked-iocs", ioc);

        log.info("✅ Ranked: {} = {} → Score: {}/10 ({})",
                ioc.getType(), ioc.getValue(), score, confidence);
    }

    private int calculateSeverity(IOC ioc) {
        int score = 5; // Start with medium score

        if (ioc.getType() == IOCType.IP) {
            // Check if IP is in suspicious list
            for (String prefix : SUSPICIOUS_IP_PREFIXES) {
                if (ioc.getValue().startsWith(prefix)) {
                    score = 8;
                    break;
                }
            }
            // Private IPs are less severe
            if (ioc.getValue().startsWith("192.168.") ||
                    ioc.getValue().startsWith("10.") ||
                    ioc.getValue().startsWith("172.")) {
                score = 2;
            }
        }
        else if (ioc.getType() == IOCType.DOMAIN) {
            // Check suspicious TLDs
            for (String tld : SUSPICIOUS_TLDS) {
                if (ioc.getValue().endsWith(tld)) {
                    score = 9;
                    break;
                }
            }
            // Short domains can be suspicious
            if (ioc.getValue().length() < 10) {
                score = Math.min(10, score + 1);
            }
        }

        // Boost based on source
        if ("AbuseIPDB".equals(ioc.getSource())) {
            score = Math.min(10, score + 1);
        } else if ("AlienVault".equals(ioc.getSource())) {
            score = Math.min(10, score + 2);
        }

        return Math.max(1, Math.min(10, score)); // Clamp between 1-10
    }

    private String getConfidence(int score) {
        if (score >= 8) return "HIGH";
        if (score >= 5) return "MEDIUM";
        return "LOW";
    }

    private List<String> getCategories(IOC ioc, int score) {
        if (score >= 8) {
            return Arrays.asList("malicious", "high_risk");
        } else if (score >= 5) {
            return Arrays.asList("suspicious", "medium_risk");
        } else {
            return Arrays.asList("low_risk", "informational");
        }
    }
}