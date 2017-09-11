package org.jenkinsci.plugins.kubesecrets.mapper;

import com.cloudbees.plugins.credentials.Credentials;
import com.cloudbees.plugins.credentials.CredentialsScope;
import com.cloudbees.plugins.credentials.impl.UsernamePasswordCredentialsImpl;
import hudson.Extension;
import org.jenkinsci.plugins.kubesecrets.ParsedSecret;

@Extension
public class UsernamePasswordSecretMapper extends AbstractKubernetesSecretMapper {
    @Override
    public Credentials getCredential(ParsedSecret parsedSecret) {
        return new UsernamePasswordCredentialsImpl(
                CredentialsScope.GLOBAL,
                parsedSecret.getId(),
                parsedSecret.getDescription(),
                getSecretOrEmpty(parsedSecret, "username").getPlainText(),
                getSecretOrEmpty(parsedSecret, "password").getPlainText()
        );
    }
}
