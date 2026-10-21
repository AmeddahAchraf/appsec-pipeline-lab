package dev.ameddah.notes;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.jwt;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.jayway.jsonpath.JsonPath;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.RequestPostProcessor;

/**
 * Security requirements as executable tests. Each test name maps to an SR-xx row in
 * docs/security-requirements.md, so every control has evidence.
 */
@SpringBootTest
@AutoConfigureMockMvc
class NoteAccessTest {

    @Autowired
    MockMvc mvc;

    static RequestPostProcessor user(String sub, String tenant) {
        return jwt().jwt(j -> j.subject(sub).claim("tenant", tenant));
    }

    long createNote(RequestPostProcessor who, String title) throws Exception {
        String json = mvc.perform(post("/api/notes").with(who)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"title\":\"" + title + "\",\"body\":\"secret\"}"))
                .andExpect(status().isCreated())
                .andReturn().getResponse().getContentAsString();
        return ((Number) JsonPath.read(json, "$.id")).longValue();
    }

    @Test
    void sr01_ownerCanReadOwnNote() throws Exception {
        long id = createNote(user("alice", "gym-a"), "mine");
        mvc.perform(get("/api/notes/" + id).with(user("alice", "gym-a")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.title").value("mine"));
    }

    @Test
    void sr01_otherUserInSameTenantGets404() throws Exception {
        long id = createNote(user("alice", "gym-a"), "private");
        mvc.perform(get("/api/notes/" + id).with(user("bob", "gym-a"))).andExpect(status().isNotFound());
        mvc.perform(delete("/api/notes/" + id).with(user("bob", "gym-a"))).andExpect(status().isNotFound());
    }

    @Test
    void sr01_sameUserIdInOtherTenantGets404() throws Exception {
        long id = createNote(user("alice", "gym-a"), "tenant scoped");
        mvc.perform(get("/api/notes/" + id).with(user("alice", "gym-b"))).andExpect(status().isNotFound());
    }

    @Test
    void sr02_requestsWithoutTokenAreRejected() throws Exception {
        mvc.perform(get("/api/notes")).andExpect(status().isUnauthorized());
    }

    @Test
    void sr02_ownerIsTakenFromTokenNotBody() throws Exception {
        String json = mvc.perform(post("/api/notes").with(user("alice", "gym-a"))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"title\":\"spoof\",\"body\":\"x\",\"ownerId\":\"bob\"}"))
                .andExpect(status().isCreated())
                .andReturn().getResponse().getContentAsString();
        long id = ((Number) JsonPath.read(json, "$.id")).longValue();
        mvc.perform(get("/api/notes/" + id).with(user("bob", "gym-a"))).andExpect(status().isNotFound());
    }

    @Test
    void sr03_oversizedTitleIsRejected() throws Exception {
        mvc.perform(post("/api/notes").with(user("alice", "gym-a"))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"title\":\"" + "x".repeat(121) + "\"}"))
                .andExpect(status().isBadRequest());
    }

    @Test
    void sr04_tokenWithoutTenantIsForbidden() throws Exception {
        mvc.perform(get("/api/notes").with(jwt().jwt(j -> j.subject("alice"))))
                .andExpect(status().isForbidden());
    }

    @Test
    void sr05_unknownPathsAreDenied() throws Exception {
        mvc.perform(get("/admin").with(user("alice", "gym-a"))).andExpect(status().isForbidden());
    }
}
