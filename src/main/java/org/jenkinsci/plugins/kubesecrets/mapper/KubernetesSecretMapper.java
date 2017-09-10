package org.jenkinsci.plugins.kubesecrets.mapper;

import com.cloudbees.plugins.credentials.Credentials;
import hudson.ExtensionPoint;
import org.jenkinsci.plugins.kubesecrets.ParsedSecret;

public interface KubernetesSecretMapper extends ExtensionPoint {
    public Credentials getCredential(ParsedSecret parsedSecret);

    public String getName();
}
