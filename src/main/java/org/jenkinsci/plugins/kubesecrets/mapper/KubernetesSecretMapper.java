package org.jenkinsci.plugins.kubesecrets.mapper;

import com.cloudbees.plugins.credentials.Credentials;
import hudson.ExtensionPoint;
import org.jenkinsci.plugins.kubesecrets.ParsedSecret;

import javax.annotation.Nonnull;

public interface KubernetesSecretMapper extends ExtensionPoint {
    @Nonnull
    Credentials getCredential(ParsedSecret parsedSecret);

    @Nonnull
    String getName();
}
