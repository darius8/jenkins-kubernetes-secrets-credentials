package org.jenkinsci.plugins.kubesecrets;

import hudson.util.Secret;

import java.util.Map;

public class ParsedSecret {
    private final String id;
    private final String kind;
    private final String description;
    private final Map<String, Secret> secrets;

    ParsedSecret(String id, String kind, String description, Map<String, Secret> secrets) {
        this.id = id;
        this.kind = kind;
        this.description = description;
        this.secrets = secrets;
    }

    public String getId() {
        return id;
    }

    public String getKind() {
        return kind;
    }

    public String getDescription() {
        return description;
    }

    public Map<String, Secret> getSecrets() {
        return secrets;
    }
}
