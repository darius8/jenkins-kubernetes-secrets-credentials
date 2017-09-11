package org.jenkinsci.plugins.kubesecrets.mapper;

import com.cloudbees.plugins.credentials.Credentials;
import hudson.ExtensionList;
import hudson.util.Secret;
import jenkins.model.Jenkins;
import org.jenkinsci.plugins.kubesecrets.ParsedSecret;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.util.Map;

public abstract class AbstractKubernetesSecretMapper implements KubernetesSecretMapper {
    public static ExtensionList<KubernetesSecretMapper> all() {
        return Jenkins.getInstance().getExtensionList(KubernetesSecretMapper.class);
    }

    @Nullable
    public static Credentials createCredentialsFromSecret(ParsedSecret parsedSecret) {
        for (KubernetesSecretMapper mapper : all()) {
            if (mapper.getName().equals(parsedSecret.getKind())) {
                return mapper.getCredential(parsedSecret);
            }
        }

        return null;
    }

    @Nonnull
    @Override
    public String getName() {
        String simpleName = this.getClass().getSimpleName();
        if (simpleName.endsWith("SecretMapper")) {
            return simpleName.substring(0, simpleName.length() - 12);
        }

        throw new RuntimeException("Could not automatically determine name for KubernetesSecretMapper implementation. " +
                "Either implement \"public String getName();\" or ensure class is in format \"<Name>SecretMapper\" " +
                "where \"<Name>\" would be the value of what should be returned."
        );
    }

    @Nonnull
    Secret getSecretOrEmpty(ParsedSecret parsedSecret, String secretKey) {
        Map<String, Secret> secrets = parsedSecret.getSecrets();
        return secrets.containsKey(secretKey) && secrets.get(secretKey) != null ? secrets.get(secretKey) : Secret.fromString("");
    }
}
