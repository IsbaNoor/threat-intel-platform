package com.threatintel.processing_service.service;

import com.threatintel.common.dto.IOC;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.kafka.annotation.KafkaListener;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

@Slf4j
@Service
@RequiredArgsConstructor
public class ProcessingService {

    private final KafkaTemplate<String, IOC> kafkaTemplate;
    private final StringRedisTemplate redisTemplate;

    @Value("${processing.whitelist:localhost,127.0.0.1}")
    private String whitelistConfig;

    private Set<String> whitelist;

    @KafkaListener(topics = "enriched-iocs", groupId = "processing-group")
    public void processIOC(IOC ioc) {
        log.info("📥 Processing: {} = {}", ioc.getType(), ioc.getValue());

        // Initialize whitelist
        if (whitelist == null) {
            whitelist = new HashSet<>(Arrays.asList(whitelistConfig.split(",")));
        }

        // 1. Check whitelist
        if (whitelist.contains(ioc.getValue())) {
            log.info("⏭️ Skipping whitelisted: {}", ioc.getValue());
            return;
        }

        // 2. Check duplicate in Redis (24 hour memory)
        String redisKey = "ioc:" + ioc.getType() + ":" + ioc.getValue();
        Boolean isNew = redisTemplate.opsForValue().setIfAbsent(redisKey, "1", Duration.ofHours(24));

        if (Boolean.FALSE.equals(isNew)) {
            log.info("⏭️ Skipping duplicate (seen in last 24h): {}", ioc.getValue());
            return;
        }

        // 3. Validated! Send to next topic
        ioc.setValidated(true);
        ioc.setProcessedAt(java.time.LocalDateTime.now());

        kafkaTemplate.send("validated-iocs", ioc);
        log.info("✅ Validated and forwarded: {}", ioc.getValue());
    }
}