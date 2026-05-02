package com.threatintel.extraction_service;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class ExtractionServiceApplication {

	public static void main(String[] args) {
		SpringApplication.run(ExtractionServiceApplication.class, args);
		System.out.println("=========================================");
		System.out.println("Extraction Service Started on Port: 8082");
		System.out.println("Consuming from: raw-threat-data");
		System.out.println("Producing to: enriched-iocs");
		System.out.println("=========================================");
	}
}