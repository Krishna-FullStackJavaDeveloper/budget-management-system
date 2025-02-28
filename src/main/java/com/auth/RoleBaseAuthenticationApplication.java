package com.auth;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.scheduling.annotation.EnableScheduling;

@SpringBootApplication
@EnableScheduling
public class RoleBaseAuthenticationApplication {

	public static void main(String[] args) {
		SpringApplication.run(RoleBaseAuthenticationApplication.class, args);

		String javaOpts = System.getenv("JAVA_OPTS");
		// Print the JAVA_OPTS for debugging purposes
		System.out.println("JAVA_OPTS: " + javaOpts);
		/*What This Means?
				-Xms512m: Sets the initial heap size to 512 MB.
				-Xmx4g: Sets the maximum heap size to 4 GB.
				-XX:+UseG1GC: Enables the G1 garbage collector, which is optimized for applications that run on large heaps.
		-XX:MaxGCPauseMillis=200: Sets a target for the maximum pause time during garbage collection to 200 milliseconds.*/
	}

}
