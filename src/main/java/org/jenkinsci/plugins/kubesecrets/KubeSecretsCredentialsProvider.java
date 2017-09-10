package org.jenkinsci.plugins.kubesecrets;

import com.cloudbees.plugins.credentials.Credentials;
import com.cloudbees.plugins.credentials.CredentialsMatcher;
import com.cloudbees.plugins.credentials.CredentialsProvider;
import com.cloudbees.plugins.credentials.CredentialsStore;
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
import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLSession;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.io.IOException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.logging.Logger;
import java.util.stream.Collectors;

import static com.cloudbees.plugins.credentials.CredentialsMatchers.*;
import static com.cloudbees.plugins.credentials.CredentialsScope.SYSTEM;

@Extension
public class KubeSecretsCredentialsProvider extends CredentialsProvider {
    private static final Logger LOGGER = Logger.getLogger(KubeSecretsCredentialsProvider.class.getName());

    // Create a trust manager that does not validate certificate chains
    private TrustManager[] trustAllCerts = new TrustManager[]{new X509TrustManager() {
        public X509Certificate[] getAcceptedIssuers() {
            return null;
        }

        public void checkClientTrusted(X509Certificate[] certs, String authType) {
        }

        public void checkServerTrusted(X509Certificate[] certs, String authType) {
        }
    }
    };
    // Create all-trusting host name verifier
    HostnameVerifier allHostsValid = new HostnameVerifier() {
        public boolean verify(String hostname, SSLSession session) {
            return true;
        }
    };
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
            if (secrets.size() > 0) {
                credentialsArray.addAll(DomainCredentials.getCredentials(getDomainListMap(domain, secrets), type, domainRequirements, matcher));
            }
        });

        return credentialsArray;
    }

    private List<CloudSecrets> getSecretsForAllClouds() {
        KubernetesSecretConfig secretConfig = KubernetesSecretConfig.get();

        List<KubernetesCloud> clouds = Jenkins.getInstance().clouds.getAll(KubernetesCloud.class);

        CredentialsStore store = CredentialsProvider.lookupStores(Jenkins.getInstance()).iterator().next();
        List<CloudSecrets> cloudSecretsStream = clouds.stream()
                .map(cloud -> {
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

                    return new CloudSecrets(cloud, domain, secret);
                })
                .collect(Collectors.toList());

        return cloudSecretsStream;
    }

    private Map<Domain, List<Credentials>> getDomainListMap(Domain domain, List<ParsedSecret> parsedSecrets) {
        Map<Domain, List<Credentials>> domainCredentialsMap = new CopyOnWriteMap.Hash<>();
        if (!domainCredentialsMap.containsKey(domain)) {
            domainCredentialsMap.put(domain, new ArrayList<>());
        }

        List<Credentials> list = domainCredentialsMap.get(domain);
        parsedSecrets.stream().forEach(parsedSecret -> {
            Credentials credential = AbstractKubernetesSecretMapper.createCredentialsFromSecret(parsedSecret);
            if (credential != null && !list.contains(credential)) {
                list.add(credential);
            }
        });

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

        List<ParsedSecret> parsedSecrets = ParsedSecretReader.getConfig(cloud, secret, filePathOrConfigMapName);
        skipGetCredentials = false;

        return parsedSecrets;
    }
}
