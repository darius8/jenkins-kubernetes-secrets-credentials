package org.jenkinsci.plugins.kubesecrets.mapper;

import com.cloudbees.plugins.credentials.Credentials;
import com.cloudbees.plugins.credentials.CredentialsScope;
import hudson.Extension;
import org.csanchez.jenkins.plugins.kubernetes.OpenShiftBearerTokenCredentialImpl;
import org.jenkinsci.plugins.kubesecrets.ParsedSecret;

@Extension
public class OpenShiftUsernamePasswordSecretMapper extends AbstractKubernetesSecretMapper {
    @Override
    public Credentials getCredential(ParsedSecret parsedSecret) {
        return new OpenShiftBearerTokenCredentialImpl(
                CredentialsScope.GLOBAL,
                parsedSecret.getId(),
                parsedSecret.getDescription(),
                parsedSecret.getSecrets().get("username").getPlainText(),
                parsedSecret.getSecrets().get("password").getPlainText()
        );
    }
}
