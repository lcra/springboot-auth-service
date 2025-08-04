package com.luke.auth;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;

@SpringBootTest
@ActiveProfiles("test")
class RbacBackendApplicationTests {

	@Test
	void contextLoads() {
		// Test that the Spring Boot application context loads successfully
		// This verifies that all beans are properly configured and wired
	}

	@Test
	void applicationStartsWithTestProfile() {
		// This test ensures that the application can start with the test profile
		// and all test-specific configurations are properly applied
	}
}
