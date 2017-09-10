package org.jenkinsci.plugins.kubesecrets.mapper;

import com.cloudbees.plugins.credentials.Credentials;
import com.cloudbees.plugins.credentials.CredentialsScope;
import com.cloudbees.plugins.credentials.impl.UsernamePasswordCredentialsImpl;
import hudson.Extension;
import org.csanchez.jenkins.plugins.kubernetes.OpenShiftTokenCredentialImpl;
import org.jenkinsci.plugins.kubesecrets.ParsedSecret;

@Extension
public class OpenShiftOAuthTokenSecretMapper extends AbstractKubernetesSecretMapper {
    @Override
    public Credentials getCredential(ParsedSecret parsedSecret) {
        return new OpenShiftTokenCredentialImpl(
                CredentialsScope.GLOBAL,
                parsedSecret.getId(),
                parsedSecret.getDescription(),
                parsedSecret.getSecrets().get("token")
        );
    }
}
