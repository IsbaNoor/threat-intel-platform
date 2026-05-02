package com.threatintel.extraction_service.service;


import com.threatintel.common.dto.IOC;
import com.threatintel.extraction_service.util.IOCExtractor;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.kafka.annotation.KafkaListener;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.kafka.support.Acknowledgment;
import org.springframework.stereotype.Service;

import java.util.List;

@Slf4j
@Service
@RequiredArgsConstructor
public class ExtractionService {

    private final KafkaTemplate<String, IOC> kafkaTemplate;
    private final IOCExtractor iocExtractor;

    private static final String RAW_THREAT_TOPIC = "raw-threat-data";
    private static final String ENRICHED_IOCS_TOPIC = "enriched-iocs";

    /**
     * Consumes raw threat data from Kafka, extracts IOCs, and publishes to enriched-iocs topic
     */
    @KafkaListener(
            topics = RAW_THREAT_TOPIC,
            groupId = "extraction-service-group",
            containerFactory = "kafkaListenerContainerFactory"
    )
    public void processRawThreatData(IOC rawIOC, Acknowledgment acknowledgment) {
        log.info("Received raw threat data from source: {}", rawIOC.getSource());

        try {
            // Extract IOCs from raw data
            List<IOC> extractedIOCs = iocExtractor.extractIOCs(
                    rawIOC.getRawData() != null ? rawIOC.getRawData() : rawIOC.toString(),
                    rawIOC.getSource()
            );

            // If the raw data already contains a direct IOC (from manual input)
            if (rawIOC.getValue() != null && rawIOC.getType() != null) {
                log.info("Direct IOC received: {} = {}", rawIOC.getType(), rawIOC.getValue());
                rawIOC.setProcessedAt(java.time.LocalDateTime.now());
                rawIOC.setValidated(true);
                kafkaTemplate.send(ENRICHED_IOCS_TOPIC, rawIOC);
            }

            // Publish each extracted IOC to Kafka
            for (IOC extracted : extractedIOCs) {
                kafkaTemplate.send(ENRICHED_IOCS_TOPIC, extracted);
                log.info("Published extracted IOC: {} = {}", extracted.getType(), extracted.getValue());
            }

            // Manually acknowledge message after successful processing
            acknowledgment.acknowledge();

            log.info("Successfully processed and extracted {} IOCs", extractedIOCs.size());

        } catch (Exception e) {
            log.error("Error processing raw threat data: {}", e.getMessage(), e);
            // Don't acknowledge - message will be retried
            throw new RuntimeException("Failed to process raw threat data", e);
        }
    }
}
