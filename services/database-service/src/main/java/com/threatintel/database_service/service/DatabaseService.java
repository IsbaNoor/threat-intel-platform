package com.threatintel.database_service.service;

import com.threatintel.common.dto.IOC;
import com.threatintel.database_service.entity.IOCEntity;
import com.threatintel.database_service.repository.IOCRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.kafka.annotation.KafkaListener;
import org.springframework.stereotype.Service;
import java.time.LocalDateTime;

@Slf4j
@Service
@RequiredArgsConstructor
public class DatabaseService {

    private final IOCRepository repository;

    @KafkaListener(topics = "ranked-iocs", groupId = "database-group")
    public void saveToDatabase(IOC ioc) {
        log.info("💾 Saving to database: {} = {}", ioc.getType(), ioc.getValue());

        try {
            // Convert DTO to Entity
            IOCEntity entity = IOCEntity.builder()
                    .iocType(ioc.getType().toString())
                    .iocValue(ioc.getValue())
                    .source(ioc.getSource())
                    .severityScore(ioc.getSeverityScore())
                    .confidence(ioc.getConfidence())
                    .categories(ioc.getCategories() != null ? String.join(",", ioc.getCategories()) : null)
                    .processedAt(ioc.getProcessedAt())
                    .build();

            // Save to database
            repository.save(entity);

            log.info("✅ Saved to database! ID: {}, Value: {}, Score: {}/10",
                    entity.getId(), entity.getIocValue(), entity.getSeverityScore());

        } catch (Exception e) {
            log.error("❌ Failed to save to database: {}", e.getMessage());
        }
    }
}