package org.jenkinsci.plugins.kubesecrets;

import com.cloudbees.plugins.credentials.Credentials;
import com.cloudbees.plugins.credentials.CredentialsMatcher;
import com.cloudbees.plugins.credentials.CredentialsProvider;
import com.cloudbees.plugins.credentials.CredentialsStore;
import com.cloudbees.plugins.credentials.common.IdCredentials;
import com.cloudbees.plugins.credentials.domains.Domain;
import com.cloudbees.plugins.credentials.domains.DomainCredentials;
import com.cloudbees.plugins.credentials.domains.DomainRequirement;
import hudson.Extension;
import hudson.model.ItemGroup;
import hudson.security.ACL;
import hudson.util.CopyOnWriteMap;
import io.fabric8.kubernetes.api.model.Secret;
import jenkins.model.Jenkins;
import org.acegisecurity.Authentication;
import org.csanchez.jenkins.plugins.kubernetes.KubernetesCloud;
import org.jenkinsci.plugins.kubesecrets.mapper.AbstractKubernetesSecretMapper;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.io.IOException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateEncodingException;
import java.util.*;
import java.util.logging.Logger;

import static com.cloudbees.plugins.credentials.CredentialsMatchers.*;
import static com.cloudbees.plugins.credentials.CredentialsScope.SYSTEM;

@Extension
public class KubeSecretsCredentialsProvider extends CredentialsProvider {
    private static final Logger LOGGER = Logger.getLogger(KubeSecretsCredentialsProvider.class.getName());

    private final Map<Domain, List<Credentials>> domainCredentialsMap = new CopyOnWriteMap.Hash<>();

    private boolean skipGetCredentials;

    /**
     * {@inheritDoc}
     */
    @Nonnull
    @Override
    public <C extends Credentials> List<C> getCredentials(
            @Nonnull Class<C> type,
            @Nullable ItemGroup itemGroup,
            @Nullable Authentication authentication
    ) {
        return getCredentials(type, itemGroup, authentication, Collections.<DomainRequirement>emptyList());
    }

    @Nonnull
    @Override
    public <C extends Credentials> List<C> getCredentials(
            @Nonnull Class<C> type,
            @Nullable ItemGroup itemGroup,
            @Nullable Authentication authentication,
            @Nonnull List<DomainRequirement> domainRequirements
    ) {
        ArrayList<C> credentialsArray = new ArrayList<>();
        if (skipGetCredentials || !ACL.SYSTEM.equals(authentication)) {
            return credentialsArray;
        }

        CredentialsMatcher matcher = Jenkins.getInstance() == itemGroup ? always() : not(withScope(SYSTEM));
        getSecretsForAllClouds().stream().forEach(cloudSecrets -> {
            Domain domain = cloudSecrets.getCredentialsDomain();
            List<ParsedSecret> secrets = cloudSecrets.getSecret();
            LOGGER.fine("Adding " + secrets.size() + " secrets for cloud " + cloudSecrets.getCloud().getDisplayName());
            if (secrets.size() > 0) {
                credentialsArray.addAll(DomainCredentials.getCredentials(getDomainListMap(domain, secrets), type, domainRequirements, matcher));
            }
        });

        LOGGER.fine("Found " + credentialsArray.size() + " credentials in clouds");
        return credentialsArray;
    }

    private List<CloudSecrets> getSecretsForAllClouds() {
        KubernetesSecretConfig secretConfig = KubernetesSecretConfig.get();

        List<KubernetesCloud> clouds = Jenkins.getInstance().clouds.getAll(KubernetesCloud.class);

        CredentialsStore store = CredentialsProvider.lookupStores(Jenkins.getInstance()).iterator().next();

        List<CloudSecrets> cloudSecrets = new LinkedList<>();
        for (KubernetesCloud cloud : clouds) {
            String domainName = cloud.getDisplayName() + " Secrets";

            Domain domain = new Domain(domainName, "Created by kubernetes-secrets plugin", null);
            try {
                store.addDomain(domain);
            } catch (IOException e) {
                LOGGER.warning("Could not create domain for kubernetes cloud " + cloud.getDisplayName());
                e.printStackTrace();
            }

            List<ParsedSecret> secret = null;
            try {
                secret = getSecretsForCloud(cloud, secretConfig.getSecretName(), secretConfig.getConfigMapName());
            } catch (UnrecoverableKeyException | CertificateEncodingException | NoSuchAlgorithmException | KeyStoreException | IOException e) {
                LOGGER.warning("Error while trying to retrieve Kubernetes secrets for cloud " + cloud.getDisplayName());
                e.printStackTrace();
            }

            cloudSecrets.add(new CloudSecrets(cloud, domain, secret));
        }

        return cloudSecrets;
    }

    private Map<Domain, List<Credentials>> getDomainListMap(Domain domain, List<ParsedSecret> parsedSecrets) {
        if (!domainCredentialsMap.containsKey(domain)) {
            domainCredentialsMap.put(domain, new ArrayList<>());
        }

        List<Credentials> list = domainCredentialsMap.get(domain);
        Map<String, Credentials> toBeAdded = new HashMap<>();
        parsedSecrets.stream().forEach(parsedSecret -> {
            IdCredentials credential = (IdCredentials) AbstractKubernetesSecretMapper.createCredentialsFromSecret(parsedSecret);
            if (credential != null) {
                if (!toBeAdded.containsKey(credential.getId())) {
                    toBeAdded.put(credential.getId(), credential);
                }
            }
        });

        List<Credentials> toBeRemoved = new LinkedList<>();
        for (Credentials credentials1 : list) {
            IdCredentials idCredential = (IdCredentials) credentials1;
            if (!toBeAdded.containsKey(idCredential.getId())) {
                toBeRemoved.add(credentials1);
                LOGGER.fine("Removed credential " + idCredential.getId());
            } else if (list.contains(credentials1)) {
                toBeRemoved.add(credentials1);
                LOGGER.fine("Will update credential " + idCredential.getId());
            } else {
                LOGGER.fine("Will add credential " + idCredential.getId());
            }
        }

        list.removeAll(toBeRemoved);
        list.addAll(toBeAdded.values());

        return domainCredentialsMap;
    }

    private List<ParsedSecret> getSecretsForCloud(
            KubernetesCloud cloud,
            String secretsName,
            String filePathOrConfigMapName
    ) throws UnrecoverableKeyException, CertificateEncodingException, NoSuchAlgorithmException, KeyStoreException, IOException {
        // todo, need to find a better way to skip getCredentials(). Currently it's getting into an infinite call back loop.
        skipGetCredentials = true;
        Secret secret = cloud.connect()
                .secrets()
                .inNamespace(cloud.getNamespace())
                .withName(secretsName)
                .get();

        if (secret == null) {
            LOGGER.warning("Could not find any secrets in \"" + cloud.getNamespace() + "." + secretsName + "\". Ensure the secrets exist.");
            return null;
        }

        List<ParsedSecret> parsedSecrets = null;
        try {
            parsedSecrets = ParsedSecretReader.getConfig(cloud, secret, filePathOrConfigMapName);
        } catch (UnrecoverableKeyException | CertificateEncodingException | NoSuchAlgorithmException | KeyStoreException | IOException e) {
            LOGGER.warning("Could not get config for kubernetes secrets in \"" + filePathOrConfigMapName + "\". Ensure file or configmap exists");
            e.printStackTrace();
        } finally {
            skipGetCredentials = false;
        }
        return parsedSecrets;

    }
}
