package com.threatintel.extraction_service.controller;


import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/v1/extraction")
public class HealthController {

    @GetMapping("/health")
    public ResponseEntity<Map<String, String>> health() {
        Map<String, String> status = new HashMap<>();
        status.put("status", "UP");
        status.put("service", "extraction-service");
        status.put("port", "8082");
        status.put("kafka", "connected");
        return ResponseEntity.ok(status);
    }

    @GetMapping("/info")
    public ResponseEntity<Map<String, Object>> info() {
        Map<String, Object> info = new HashMap<>();
        info.put("name", "Extraction Service");
        info.put("version", "1.0.0");
        info.put("description", "Extracts IPs and Domains from raw threat data");
        info.put("topics", Map.of(
                "consumes", "raw-threat-data",
                "produces", "enriched-iocs"
        ));
        return ResponseEntity.ok(info);
    }
}