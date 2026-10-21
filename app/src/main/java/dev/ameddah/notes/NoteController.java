package dev.ameddah.notes;

import java.net.URI;
import java.util.List;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

@RestController
@RequestMapping("/api/notes")
public class NoteController {

    /** SR-03: input is validated at the edge. Limits match the database columns. */
    public record NoteRequest(@NotBlank @Size(max = 120) String title, @Size(max = 4000) String body) {
    }

    public record NoteResponse(Long id, String title, String body) {
        static NoteResponse of(Note n) {
            return new NoteResponse(n.getId(), n.getTitle(), n.getBody());
        }
    }

    private final NoteRepository notes;

    public NoteController(NoteRepository notes) {
        this.notes = notes;
    }

    @GetMapping
    public List<NoteResponse> mine(@AuthenticationPrincipal Jwt jwt) {
        return notes.findByTenantIdAndOwnerId(tenant(jwt), jwt.getSubject()).stream().map(NoteResponse::of).toList();
    }

    @PostMapping
    public ResponseEntity<NoteResponse> create(@AuthenticationPrincipal Jwt jwt, @Valid @RequestBody NoteRequest req) {
        // SR-02: owner and tenant come from the verified token, never from the request body.
        Note saved = notes.save(new Note(tenant(jwt), jwt.getSubject(), req.title(), req.body()));
        return ResponseEntity.created(URI.create("/api/notes/" + saved.getId())).body(NoteResponse.of(saved));
    }

    @GetMapping("/{id}")
    public NoteResponse one(@AuthenticationPrincipal Jwt jwt, @PathVariable Long id) {
        return NoteResponse.of(owned(jwt, id));
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<Void> delete(@AuthenticationPrincipal Jwt jwt, @PathVariable Long id) {
        notes.delete(owned(jwt, id));
        return ResponseEntity.noContent().build();
    }

    /** SR-01: 404 (not 403) for someone else's note, so attackers cannot even confirm it exists. */
    private Note owned(Jwt jwt, Long id) {
        return notes.findByIdAndTenantIdAndOwnerId(id, tenant(jwt), jwt.getSubject())
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND));
    }

    /** SR-04: a token without a tenant claim is rejected instead of falling back to a default tenant. */
    private static String tenant(Jwt jwt) {
        String tenant = jwt.getClaimAsString("tenant");
        if (tenant == null || tenant.isBlank()) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "missing tenant claim");
        }
        return tenant;
    }
}
