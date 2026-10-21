package dev.ameddah.notes;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.Id;

/** A private note. Every note belongs to exactly one user inside one tenant. */
@Entity
public class Note {

    @Id
    @GeneratedValue
    private Long id;

    @Column(nullable = false)
    private String tenantId;

    @Column(nullable = false)
    private String ownerId;

    @Column(nullable = false, length = 120)
    private String title;

    @Column(length = 4000)
    private String body;

    protected Note() {
    }

    public Note(String tenantId, String ownerId, String title, String body) {
        this.tenantId = tenantId;
        this.ownerId = ownerId;
        this.title = title;
        this.body = body;
    }

    public Long getId() {
        return id;
    }

    public String getTenantId() {
        return tenantId;
    }

    public String getOwnerId() {
        return ownerId;
    }

    public String getTitle() {
        return title;
    }

    public String getBody() {
        return body;
    }
}
