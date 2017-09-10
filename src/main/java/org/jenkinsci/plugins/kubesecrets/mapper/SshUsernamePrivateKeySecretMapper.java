package org.jenkinsci.plugins.kubesecrets.mapper;

import com.cloudbees.jenkins.plugins.sshcredentials.impl.BasicSSHUserPrivateKey;
import com.cloudbees.plugins.credentials.Credentials;
import com.cloudbees.plugins.credentials.CredentialsScope;
import com.cloudbees.plugins.credentials.impl.UsernamePasswordCredentialsImpl;
import hudson.Extension;
import hudson.util.Secret;
import org.jenkinsci.plugins.kubesecrets.ParsedSecret;

import java.util.Map;

@Extension
public class SshUsernamePrivateKeySecretMapper extends AbstractKubernetesSecretMapper {
    @Override
    public Credentials getCredential(ParsedSecret parsedSecret) {
        Map<String, Secret> secrets = parsedSecret.getSecrets();

        return new BasicSSHUserPrivateKey(
                CredentialsScope.GLOBAL,
                parsedSecret.getId(),
                secrets.get("username").getPlainText(),
                new BasicSSHUserPrivateKey.DirectEntryPrivateKeySource(secrets.get("private_key").getPlainText()),
                secrets.get("passphrase").getEncryptedValue(),
                parsedSecret.getDescription()
        );
    }
}