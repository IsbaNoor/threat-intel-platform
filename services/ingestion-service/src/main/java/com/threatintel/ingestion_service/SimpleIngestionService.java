package com.threatintel.ingestion_service;

import com.threatintel.common.dto.IOC;
import com.threatintel.common.dto.IOCType;
import lombok.extern.slf4j.Slf4j;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;

@Slf4j
@Service
@EnableScheduling
public class SimpleIngestionService {

    private final KafkaTemplate<String, IOC> kafkaTemplate;

    public SimpleIngestionService(KafkaTemplate<String, IOC> kafkaTemplate) {
        this.kafkaTemplate = kafkaTemplate;
    }

    // This runs every 5 minutes automatically
    @Scheduled(fixedDelay = 300000)
    public void fetchMockData() {
        log.info("Fetching threat data...");

        // Mock data for testing (real implementation will call actual APIs)
        IOC mockIOC = IOC.builder()
                .type(IOCType.IP)
                .value("185.130.5.253")
                .source("MockSource")
                .severityScore(7)
                .confidence("HIGH")
                .processedAt(LocalDateTime.now())
                .build();

        // Send to Kafka
        kafkaTemplate.send("raw-threat-data", mockIOC);
        log.info("Sent IOC to Kafka: {}", mockIOC.getValue());
    }
}