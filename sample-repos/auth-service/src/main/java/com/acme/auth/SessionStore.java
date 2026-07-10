package com.acme.auth;

import java.time.Instant;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/** In-memory session bookkeeping (no cryptography here). */
public class SessionStore {

    public record Session(String userId, Instant issuedAt, Instant expiresAt) {}

    private final Map<String, Session> sessions = new ConcurrentHashMap<>();

    public void put(String sessionId, Session session) {
        sessions.put(sessionId, session);
    }

    public Session get(String sessionId) {
        Session s = sessions.get(sessionId);
        if (s == null || s.expiresAt().isBefore(Instant.now())) {
            sessions.remove(sessionId);
            return null;
        }
        return s;
    }

    public int activeCount() {
        sessions.values().removeIf(s -> s.expiresAt().isBefore(Instant.now()));
        return sessions.size();
    }
}
