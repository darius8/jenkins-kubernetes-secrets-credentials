package org.jenkinsci.plugins.kubesecrets.mapper;

import com.cloudbees.plugins.credentials.Credentials;
import com.cloudbees.plugins.credentials.CredentialsScope;
import com.cloudbees.plugins.credentials.impl.UsernamePasswordCredentialsImpl;
import hudson.Extension;
import hudson.util.Secret;
import org.csanchez.jenkins.plugins.kubernetes.OpenShiftTokenCredentialImpl;
import org.jenkinsci.plugins.kubesecrets.ParsedSecret;

import javax.annotation.Nonnull;
import java.util.Map;

@Extension
public class OpenShiftOAuthTokenSecretMapper extends AbstractKubernetesSecretMapper {
    @Nonnull
    @Override
    public Credentials getCredential(ParsedSecret parsedSecret) {
        Map<String, Secret> secrets = parsedSecret.getSecrets();

        return new OpenShiftTokenCredentialImpl(
                CredentialsScope.GLOBAL,
                parsedSecret.getId(),
                parsedSecret.getDescription(),
                getSecretOrEmpty(parsedSecret, "token")
        );
    }
}
