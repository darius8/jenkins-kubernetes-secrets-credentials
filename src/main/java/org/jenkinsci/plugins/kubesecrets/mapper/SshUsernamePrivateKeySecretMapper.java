package org.jenkinsci.plugins.kubesecrets.mapper;

import com.cloudbees.jenkins.plugins.sshcredentials.impl.BasicSSHUserPrivateKey;
import com.cloudbees.plugins.credentials.Credentials;
import com.cloudbees.plugins.credentials.CredentialsScope;
import com.cloudbees.plugins.credentials.impl.UsernamePasswordCredentialsImpl;
import hudson.Extension;
import hudson.util.Secret;
import org.jenkinsci.plugins.kubesecrets.ParsedSecret;

import javax.annotation.Nonnull;
import java.util.Map;

@Extension
public class SshUsernamePrivateKeySecretMapper extends AbstractKubernetesSecretMapper {
    @Nonnull
    @Override
    public Credentials getCredential(ParsedSecret parsedSecret) {
        return new BasicSSHUserPrivateKey(
                CredentialsScope.GLOBAL,
                parsedSecret.getId(),
                getSecretOrEmpty(parsedSecret, "username").getPlainText(),
                new BasicSSHUserPrivateKey.DirectEntryPrivateKeySource(getSecretOrEmpty(parsedSecret, "private_key").getPlainText()),
                getSecretOrEmpty(parsedSecret, "passphrase").getPlainText(),
                parsedSecret.getDescription()
        );
    }
}
