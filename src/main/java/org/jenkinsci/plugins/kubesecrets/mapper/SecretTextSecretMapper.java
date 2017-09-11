package org.jenkinsci.plugins.kubesecrets.mapper;

import com.cloudbees.plugins.credentials.Credentials;
import com.cloudbees.plugins.credentials.CredentialsScope;
import com.cloudbees.plugins.credentials.impl.UsernamePasswordCredentialsImpl;
import hudson.Extension;
import org.jenkinsci.plugins.kubesecrets.ParsedSecret;
import org.jenkinsci.plugins.plaincredentials.impl.StringCredentialsImpl;

import javax.annotation.Nonnull;

@Extension
public class SecretTextSecretMapper extends AbstractKubernetesSecretMapper {
    @Nonnull
    @Override
    public Credentials getCredential(ParsedSecret parsedSecret) {
        return new StringCredentialsImpl(
                CredentialsScope.GLOBAL,
                parsedSecret.getId(),
                parsedSecret.getDescription(),
                getSecretOrEmpty(parsedSecret, "secret")
        );
    }
}
