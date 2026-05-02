package com.threatintel.query_service.service;

import com.threatintel.common.dto.IOC;
import com.threatintel.database_service.entity.IOCEntity;
import com.threatintel.database_service.repository.IOCRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import java.util.List;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class QueryService {

    private final IOCRepository repository;

    public List<IOC> searchByValue(String value) {
        List<IOCEntity> entities = repository.findAll();
        return entities.stream()
                .filter(e -> e.getValue().contains(value))
                .map(this::convertToDTO)
                .collect(Collectors.toList());
    }

    public long getTotalCount() {
        return repository.count();
    }

    private IOC convertToDTO(IOCEntity entity) {
        return IOC.builder()
                .type(entity.getType())
                .value(entity.getValue().toString())
                .source(entity.getSource())
                .severityScore(entity.getSeverityScore())
                .processedAt(entity.getProcessedAt())
                .build();
    }
}