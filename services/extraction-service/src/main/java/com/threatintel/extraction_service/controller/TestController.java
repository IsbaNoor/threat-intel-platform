package com.threatintel.extraction_service.controller;

import com.threatintel.common.dto.IOC;
import com.threatintel.common.dto.IOCType;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.web.bind.annotation.*;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;

@Slf4j
@RestController
@RequestMapping("/api/v1/extraction")
@RequiredArgsConstructor
public class TestController {

    private final KafkaTemplate<String, IOC> kafkaTemplate;
    private static final String TOPIC = "raw-threat-data";

    @PostMapping("/test")
    public Map<String, String> sendTestMessage(@RequestBody Map<String, String> request) {
        String source = request.getOrDefault("source", "PostmanTest");
        String rawData = request.get("rawData");

        IOC ioc = IOC.builder()
                .source(source)
                .rawData(rawData)
                .processedAt(LocalDateTime.now())
                .build();

        kafkaTemplate.send(TOPIC, ioc);

        log.info("📤 Sent test message to Kafka: {}", rawData);

        Map<String, String> response = new HashMap<>();
        response.put("status", "sent");
        response.put("message", "Test message sent to Kafka");
        response.put("data", rawData);
        return response;
    }
}