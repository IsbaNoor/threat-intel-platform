package com.threatintel.ranking_service;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;


@SpringBootApplication
public class RankingServiceApplication {
	public static void main(String[] args) {
		SpringApplication.run(RankingServiceApplication.class, args);
		System.out.println("✅ Ranking Service Started on port 8084");
		System.out.println("📍 Listening to: validated-iocs");
		System.out.println("📍 Sending to: ranked-iocs");
		System.out.println("⭐ Scoring mode: MOCK (fallback enabled)");
	}
}