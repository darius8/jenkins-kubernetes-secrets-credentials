package org.jenkinsci.plugins.kubesecrets.mapper;

import com.cloudbees.plugins.credentials.Credentials;
import com.cloudbees.plugins.credentials.CredentialsScope;
import hudson.Extension;
import org.csanchez.jenkins.plugins.kubernetes.OpenShiftBearerTokenCredentialImpl;
import org.jenkinsci.plugins.kubesecrets.ParsedSecret;

import javax.annotation.Nonnull;

@Extension
public class OpenShiftUsernamePasswordSecretMapper extends AbstractKubernetesSecretMapper {
    @Nonnull
    @Override
    public Credentials getCredential(ParsedSecret parsedSecret) {
        return new OpenShiftBearerTokenCredentialImpl(
                CredentialsScope.GLOBAL,
                parsedSecret.getId(),
                parsedSecret.getDescription(),
                getSecretOrEmpty(parsedSecret, "username").getPlainText(),
                getSecretOrEmpty(parsedSecret, "password").getPlainText()
        );
    }
}
