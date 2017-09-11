package org.jenkinsci.plugins.kubesecrets.mapper;

import com.cloudbees.plugins.credentials.Credentials;
import com.cloudbees.plugins.credentials.CredentialsScope;
import com.cloudbees.plugins.credentials.impl.UsernamePasswordCredentialsImpl;
import hudson.Extension;
import org.jenkinsci.plugins.kubesecrets.ParsedSecret;
import org.jenkinsci.plugins.plaincredentials.impl.StringCredentialsImpl;

@Extension
public class SecretTextSecretMapper extends AbstractKubernetesSecretMapper {
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
