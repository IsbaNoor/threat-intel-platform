package com.threatintel.database_service;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;


@SpringBootApplication
public class DatabaseServiceApplication {
	public static void main(String[] args) {
		SpringApplication.run(DatabaseServiceApplication.class, args);
		System.out.println("✅ Database Service Started on port 8085");
		System.out.println("📍 Listening to: ranked-iocs");
		System.out.println("📍 Saving to: MySQL Database");
	}
}
