package dev.ameddah.notes;

import static org.assertj.core.api.Assertions.assertThat;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Instant;

import com.jayway.jsonpath.JsonPath;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.context.annotation.Bean;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;

/**
 * SR-01 over a real HTTP server. MockMvc does not forward errors to /error, so it missed a bug
 * where the security chain turned every 404 into a 403. This test runs the full servlet error path.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class ErrorStatusOverHttpTest {

    /** Test-only decoder: the bearer value is the user name, all users are in gym-a. */
    @TestConfiguration
    static class FakeTokens {
        @Bean
        JwtDecoder jwtDecoder() {
            return token -> Jwt.withTokenValue(token)
                    .header("alg", "none")
                    .subject(token)
                    .claim("tenant", "gym-a")
                    .issuedAt(Instant.now())
                    .expiresAt(Instant.now().plusSeconds(60))
                    .build();
        }
    }

    @LocalServerPort
    int port;

    final HttpClient http = HttpClient.newHttpClient();

    HttpResponse<String> send(HttpRequest.Builder req, String user) throws Exception {
        return http.send(req.header("Authorization", "Bearer " + user).build(), HttpResponse.BodyHandlers.ofString());
    }

    URI uri(String path) {
        return URI.create("http://localhost:" + port + path);
    }

    @Test
    void sr01_otherUserGets404NotForbidden() throws Exception {
        HttpResponse<String> created = send(HttpRequest.newBuilder(uri("/api/notes"))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString("{\"title\":\"private\",\"body\":\"secret\"}")), "alice");
        assertThat(created.statusCode()).isEqualTo(201);
        long id = ((Number) JsonPath.read(created.body(), "$.id")).longValue();

        assertThat(send(HttpRequest.newBuilder(uri("/api/notes/" + id)), "bob").statusCode()).isEqualTo(404);
        assertThat(send(HttpRequest.newBuilder(uri("/api/notes/999999")), "alice").statusCode()).isEqualTo(404);
    }

    @Test
    void errorEndpointIsNotReachableDirectly() throws Exception {
        assertThat(send(HttpRequest.newBuilder(uri("/error")), "alice").statusCode()).isEqualTo(403);
    }
}
