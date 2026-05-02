package com.threatintel.database_service.repository;


import com.threatintel.database_service.entity.IOCEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface IOCRepository extends JpaRepository<IOCEntity, Long> {
    // JpaRepository gives us save(), findAll(), findById(), delete(), etc.
}