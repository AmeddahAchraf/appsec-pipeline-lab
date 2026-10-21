package dev.ameddah.notes;

import java.util.List;
import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

public interface NoteRepository extends JpaRepository<Note, Long> {

    List<Note> findByTenantIdAndOwnerId(String tenantId, String ownerId);

    /**
     * SR-01: object lookups are always scoped to the caller. There is deliberately no
     * public "find by id" path in the controller, so a guessed id can never leak another user's note.
     */
    Optional<Note> findByIdAndTenantIdAndOwnerId(Long id, String tenantId, String ownerId);
}
