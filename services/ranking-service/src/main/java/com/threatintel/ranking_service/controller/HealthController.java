package com.threatintel.ranking_service.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import java.util.Map;

@RestController
public class HealthController {

    @GetMapping("/health")
    public Map<String, String> health() {
        return Map.of(
                "status", "UP",
                "service", "processing-service",
                "port", "8083",
                "redis", "connected"
        );
    }

    @GetMapping("/info")
    public Map<String, Object> info() {
        return Map.of(
                "name", "Ranking Service",
                "description", "Assigns severity scores to IOCs",
                "consumes", "validated-iocs",
                "produces", "ranked-iocs",
                "scoring", Map.of(
                        "1-3", "LOW - Informational",
                        "4-6", "MEDIUM - Monitor",
                        "7-8", "HIGH - Investigate",
                        "9-10", "CRITICAL - Immediate Action"
                )
        );
    }
}