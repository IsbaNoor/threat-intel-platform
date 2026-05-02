package com.threatintel.processing_service;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;


import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class ProcessingServiceApplication {
	public static void main(String[] args) {
		SpringApplication.run(ProcessingServiceApplication.class, args);
		System.out.println("✅ Processing Service Started on port 8083");
		System.out.println("📍 Listening to: enriched-iocs");
		System.out.println("📍 Sending to: validated-iocs");
	}
}
