package org.jenkinsci.plugins.kubesecrets.mapper;

import com.cloudbees.plugins.credentials.Credentials;
import hudson.ExtensionList;
import jenkins.model.Jenkins;
import org.jenkinsci.plugins.kubesecrets.ParsedSecret;

public abstract class AbstractKubernetesSecretMapper implements KubernetesSecretMapper {
    public static ExtensionList<KubernetesSecretMapper> all() {
        return Jenkins.getInstance().getExtensionList(KubernetesSecretMapper.class);
    }

    public static Credentials createCredentialsFromSecret(ParsedSecret parsedSecret) {
        for (KubernetesSecretMapper mapper : all()) {
            if (mapper.getName().equals(parsedSecret.getKind())) {
                return mapper.getCredential(parsedSecret);
            }
        }

        return null;
    }

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
}
