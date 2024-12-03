package com.ghostappi.backend;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.scheduling.annotation.EnableScheduling;

@SpringBootApplication
@EnableScheduling
public class GhostapiApplication {

	public static void main(String[] args) {
		System.out.println("\n\n\nSPRING_DATASOURCE_URL " + System.getenv("SPRING_DATASOURCE_URL"));
		SpringApplication.run(GhostapiApplication.class, args);
	}

}
