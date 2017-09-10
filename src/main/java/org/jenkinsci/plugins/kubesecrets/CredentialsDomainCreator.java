package org.jenkinsci.plugins.kubesecrets;

import com.cloudbees.plugins.credentials.CredentialsProvider;
import com.cloudbees.plugins.credentials.CredentialsStore;
import com.cloudbees.plugins.credentials.domains.Domain;
import jenkins.model.Jenkins;
import org.csanchez.jenkins.plugins.kubernetes.KubernetesCloud;

import java.io.IOException;
import java.util.logging.Logger;

class CredentialsDomainCreator {
    private static final Logger LOGGER = Logger.getLogger(CredentialsDomainCreator.class.getName());

    static void createClusterDomains() {
        CredentialsStore store = CredentialsProvider.lookupStores(Jenkins.getInstance()).iterator().next();

        Jenkins.getInstance().clouds.getAll(KubernetesCloud.class).forEach(cloud -> {
            String domainName = cloud.getDisplayName() + " Secrets";

            Domain domain = new Domain(domainName, "Created by kubernetes-secrets plugin", null);
            try {
                store.addDomain(domain);
            } catch (IOException e) {
                LOGGER.warning("Could not create credentials domains for kubernetes cloud clusters");
                e.printStackTrace();
            }
        });
    }
}
