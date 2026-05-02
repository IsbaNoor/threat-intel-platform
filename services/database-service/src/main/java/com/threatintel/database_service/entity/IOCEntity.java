package com.threatintel.database_service.entity;

import com.threatintel.common.dto.IOCType;
import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;
import java.util.Collection;


@Entity
@Table(name = "iocs")
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class IOCEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "ioc_type", nullable = false)
    private String iocType;

    @Column(name = "ioc_value", nullable = false)
    private String iocValue;

    private String source;

    @Column(name = "severity_score")
    private Integer severityScore;

    private String confidence;

    private String categories;

    @Column(name = "processed_at")
    private LocalDateTime processedAt;

    @Column(name = "created_at")
    private LocalDateTime createdAt;

    @PrePersist
    protected void onCreate() {
        createdAt = LocalDateTime.now();
    }

    public Collection<Object> getValue() {
        return java.util.List.of();
    }

    public IOCType getType() {
        return null;
    }
}
