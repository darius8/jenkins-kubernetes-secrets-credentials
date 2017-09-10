package org.jenkinsci.plugins.kubesecrets;

import com.cloudbees.plugins.credentials.domains.Domain;
import io.fabric8.kubernetes.api.model.Secret;
import org.csanchez.jenkins.plugins.kubernetes.KubernetesCloud;

import java.util.List;

public class CloudSecrets {
    private KubernetesCloud cloud;

    private Domain credentialsDomain;

    private List<ParsedSecret> secret;

    public CloudSecrets(KubernetesCloud cloud, Domain credentialsDomain, List<ParsedSecret> secret) {
        this.cloud = cloud;
        this.credentialsDomain = credentialsDomain;
        this.secret = secret;
    }

    public KubernetesCloud getCloud() {
        return cloud;
    }

    public Domain getCredentialsDomain() {
        return credentialsDomain;
    }

    public List<ParsedSecret> getSecret() {
        return secret;
    }
}
