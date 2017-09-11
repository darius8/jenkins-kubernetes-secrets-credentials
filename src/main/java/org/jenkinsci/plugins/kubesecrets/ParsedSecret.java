package org.jenkinsci.plugins.kubesecrets;

import hudson.util.Secret;

import javax.annotation.Nonnull;
import java.util.Map;

public class ParsedSecret {
    private final String id;
    private final String kind;
    private final String description;
    private final Map<String, Secret> secrets;

    ParsedSecret(@Nonnull String id, @Nonnull String kind, String description, Map<String, Secret> secrets) {
        if (id.isEmpty()) {
            throw new IllegalArgumentException("The \"id\" property for a kubernetes secret cannot be empty");
        }

        if (kind.isEmpty()) {
            throw new IllegalArgumentException("The \"kind\" property for a kubernetes secret cannot be empty");
        }

        this.id = id;
        this.kind = kind;
        this.description = description == null ? "" : description;
        this.secrets = secrets;
    }

    @Nonnull
    public String getId() {
        return id;
    }

    @Nonnull
    public String getKind() {
        return kind;
    }

    @Nonnull
    public String getDescription() {
        return description;
    }

    @Nonnull
    public Map<String, Secret> getSecrets() {
        return secrets;
    }
}
