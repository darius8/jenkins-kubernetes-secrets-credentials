package org.jenkinsci.plugins.kubesecrets;

import com.cloudbees.plugins.credentials.*;
import com.cloudbees.plugins.credentials.Messages;
import com.cloudbees.plugins.credentials.common.IdCredentials;
import com.cloudbees.plugins.credentials.domains.Domain;
import com.cloudbees.plugins.credentials.domains.DomainCredentials;
import com.cloudbees.plugins.credentials.domains.DomainRequirement;
import edu.umd.cs.findbugs.annotations.CheckForNull;
import edu.umd.cs.findbugs.annotations.NonNull;
import edu.umd.cs.findbugs.annotations.Nullable;
import hudson.BulkChange;
import hudson.Extension;
import hudson.ExtensionList;
import hudson.model.*;
import hudson.security.ACL;
import hudson.security.Permission;
import hudson.util.CopyOnWriteMap;
import io.fabric8.kubernetes.api.model.Secret;
import jenkins.model.Jenkins;
import org.acegisecurity.Authentication;
import org.csanchez.jenkins.plugins.kubernetes.KubernetesCloud;
import org.jenkinsci.plugins.kubesecrets.mapper.AbstractKubernetesSecretMapper;
import org.jenkinsci.plugins.pipeline.modeldefinition.shaded.org.joda.time.DateTime;
import org.kohsuke.stapler.export.Exported;
import org.kohsuke.stapler.export.ExportedBean;

import java.io.IOException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateEncodingException;
import java.util.*;
import java.util.logging.Logger;

import static com.cloudbees.plugins.credentials.CredentialsMatchers.*;
import static com.cloudbees.plugins.credentials.CredentialsScope.GLOBAL;
import static com.cloudbees.plugins.credentials.CredentialsScope.SYSTEM;

@Extension
public class KubeSecretsCredentialsProvider extends AbstractDescribableImpl<KubeSecretsCredentialsProvider> {
    private static final Logger LOGGER = Logger.getLogger(KubeSecretsCredentialsProvider.class.getName());

    private final Map<Domain, List<Credentials>> domainCredentialsMap = new CopyOnWriteMap.Hash<>();

    protected static boolean skipGetCredentials;

    private int secretsRetrievalTimeoutMillis = 300000;

    private long lastRetrievedSecrets = -1;

    private transient KubeSecretsCredentialsProvider.StoreImpl store = new KubeSecretsCredentialsProvider.StoreImpl();

    public static KubeSecretsCredentialsProvider getInstance() {
        return ExtensionList.lookup(KubeSecretsCredentialsProvider.class).get(KubeSecretsCredentialsProvider.class);
    }

    @NonNull
    public synchronized Map<Domain, List<Credentials>> getDomainCredentialsMap() {
        populateCredentialsMap();
        return domainCredentialsMap;
    }

    private synchronized boolean addCredentials(@NonNull Domain domain, @NonNull Credentials credentials)
            throws IOException {
        Map<Domain, List<Credentials>> domainCredentialsMap = getDomainCredentialsMap();
        if (domainCredentialsMap.containsKey(domain)) {
            List<Credentials> list = domainCredentialsMap.get(domain);
            if (list.contains(credentials)) {
                return false;
            }
            list.add(credentials);
            return true;
        }
        return false;
    }

    @NonNull
    private synchronized List<Credentials> getCredentials(@NonNull Domain domain) {
        if (Jenkins.getInstance().hasPermission(CredentialsProvider.VIEW)) {
            List<Credentials> list = getDomainCredentialsMap().get(domain);
            if (list == null || list.isEmpty()) {
                return Collections.emptyList();
            }
            return Collections.unmodifiableList(new ArrayList<Credentials>(list));
        }
        return Collections.emptyList();
    }

    // todo do we need remove?
    private synchronized boolean removeCredentials(@NonNull Domain domain, @NonNull Credentials credentials)
            throws IOException {
        throw new IOException("Cannot remove credentials for kubernetes secrets");
    }

    private synchronized boolean updateCredentials(@NonNull Domain domain, @NonNull Credentials current,
                                                   @NonNull Credentials replacement) throws IOException {
        throw new IOException("Cannot update credentials for kubernetes secrets");
    }

    /**
     * Implementation for {@link ProviderImpl} to delegate to while keeping the lock synchronization simple.
     */
    private synchronized StoreImpl getStore() {
        if (store == null) {
            store = new StoreImpl();
        }
        return store;
    }

    private List<CloudSecrets> getSecretsForAllClouds() {
        KubernetesSecretConfig secretConfig = KubernetesSecretConfig.get();

        List<KubernetesCloud> clouds = Jenkins.getInstance().clouds.getAll(KubernetesCloud.class);

        List<CloudSecrets> cloudSecrets = new LinkedList<>();
        for (KubernetesCloud cloud : clouds) {
            Domain domain = new Domain(cloud.getDisplayName(), "Created by kubernetes-secrets plugin", null);
            // todo secretname and configmap should be different per cloud
            List<ParsedSecret> secret = getSecretsForCloud(cloud, secretConfig.getSecretName(), secretConfig.getConfigMapName());

            cloudSecrets.add(new CloudSecrets(cloud, domain, secret));
        }

        return cloudSecrets;
    }

    private synchronized Map<Domain, List<Credentials>> getDomainListMap(Domain domain, List<ParsedSecret> parsedSecrets) {
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

    private synchronized List<ParsedSecret> getSecretsForCloud(KubernetesCloud cloud, String secretsName, String filePathOrConfigMapName) {
        // todo, need to find a better way to skip getCredentials(). Currently it's getting into an infinite call back loop.
        skipGetCredentials = true;

        List<ParsedSecret> parsedSecrets = null;
        try {
            Secret secret = cloud.connect()
                    .secrets()
                    .inNamespace(cloud.getNamespace())
                    .withName(secretsName)
                    .get();

            if (secret == null) {
                LOGGER.warning("Could not find any secrets in \"" + cloud.getNamespace() + "." + secretsName + "\". Ensure the secrets exist.");
            } else {
                parsedSecrets = ParsedSecretReader.getConfig(cloud, secret, filePathOrConfigMapName);
            }
        } catch (UnrecoverableKeyException | CertificateEncodingException | NoSuchAlgorithmException | KeyStoreException | IOException e) {
            LOGGER.warning("Could not get config for kubernetes secrets in \"" + filePathOrConfigMapName + "\". Ensure file or configmap exists");
            e.printStackTrace();
        } finally {
            skipGetCredentials = false;
        }
        return parsedSecrets;
    }

    private synchronized void populateCredentialsMap() {
        if (lastRetrievedSecrets != -1 && (System.currentTimeMillis()-secretsRetrievalTimeoutMillis >= lastRetrievedSecrets)) {
            return;
        }

        lastRetrievedSecrets = System.currentTimeMillis();
        KubeSecretsCredentialsProvider credentialsProvider = KubeSecretsCredentialsProvider.getInstance();
        List<CloudSecrets> secretsForAllClouds = credentialsProvider.getSecretsForAllClouds();
        for (CloudSecrets cloudSecrets : secretsForAllClouds) {
            Domain domain = cloudSecrets.getCredentialsDomain();
            List<ParsedSecret> secrets = cloudSecrets.getSecret();
            LOGGER.fine("Adding " + secrets.size() + " secrets for cloud " + cloudSecrets.getCloud().getDisplayName());
            if (secrets.size() > 0) {
                getDomainListMap(domain, secrets);
            }
        }
    }

    @Extension
    @SuppressWarnings("unused") // used by Jenkins
    public static class ProviderImpl extends CredentialsProvider {

        /**
         * {@inheritDoc}
         */
        @Override
        public String getDisplayName() {
            return "Kubernetes Secrets Provider";
        }

        /**
         * The scopes that are relevant to the store.
         */
        private static final Set<CredentialsScope> SCOPES =
                Collections.unmodifiableSet(new LinkedHashSet<CredentialsScope>(Arrays.asList(GLOBAL, SYSTEM)));

        /**
         * {@inheritDoc}
         */
        @Override
        public Set<CredentialsScope> getScopes(ModelObject object) {
            if (object instanceof Jenkins || object instanceof KubeSecretsCredentialsProvider) {
                return SCOPES;
            }
            return super.getScopes(object);
        }

        /**
         * {@inheritDoc}
         */
        @Override
        public CredentialsStore getStore(@CheckForNull ModelObject object) {
            if (object == Jenkins.getInstance()) {
                return KubeSecretsCredentialsProvider.getInstance().getStore();
            }
            return null;
        }

        /**
         * {@inheritDoc}
         */
        @NonNull
        @Override
        public <C extends Credentials> List<C> getCredentials(
                @NonNull Class<C> type,
                @Nullable ItemGroup itemGroup,
                @Nullable Authentication authentication) {
            return getCredentials(type, itemGroup, authentication, Collections.<DomainRequirement>emptyList());
        }

        /**
         * {@inheritDoc}
         */
        @NonNull
        @Override
        public <C extends Credentials> List<C> getCredentials(
                @NonNull Class<C> type,
                @Nullable ItemGroup itemGroup,
                @Nullable Authentication authentication,
                @NonNull List<DomainRequirement> domainRequirements) {
            ArrayList<C> credentialsArray = new ArrayList<>();
            if (skipGetCredentials || !ACL.SYSTEM.equals(authentication)) {
                return credentialsArray;
            }

            CredentialsMatcher matcher = Jenkins.getInstance() == itemGroup ? always() : not(withScope(SYSTEM));
            KubeSecretsCredentialsProvider credentialsProvider = KubeSecretsCredentialsProvider.getInstance();
            List<CloudSecrets> secretsForAllClouds = credentialsProvider.getSecretsForAllClouds();
            for (CloudSecrets cloudSecrets : secretsForAllClouds) {
                Domain domain = cloudSecrets.getCredentialsDomain();
                List<ParsedSecret> secrets = cloudSecrets.getSecret();
                LOGGER.fine("Adding " + secrets.size() + " secrets for cloud " + cloudSecrets.getCloud().getDisplayName());
                if (secrets.size() > 0) {
                    credentialsArray.addAll(DomainCredentials.getCredentials(credentialsProvider.getDomainListMap(domain, secrets), type, domainRequirements, matcher));
                }
            }

            LOGGER.fine("Found " + credentialsArray.size() + " credentials in clouds");
            return credentialsArray;
        }

        /**
         * {@inheritDoc}
         */
        @NonNull
        @Override
        public <C extends Credentials> List<C> getCredentials(@NonNull Class<C> type, @NonNull Item item,
                                                              @Nullable Authentication authentication) {
            return getCredentials(type, item, authentication, Collections.<DomainRequirement>emptyList());
        }

        /**
         * {@inheritDoc}
         */
        @NonNull
        @Override
        public <C extends Credentials> List<C> getCredentials(
                @NonNull Class<C> type,
                @NonNull Item item,
                @Nullable Authentication authentication,
                @NonNull List<DomainRequirement> domainRequirements) {
            ArrayList<C> credentialsArray = new ArrayList<>();
            if (skipGetCredentials || !ACL.SYSTEM.equals(authentication)) {
                return credentialsArray;
            }

            CredentialsMatcher matcher = not(withScope(SYSTEM));
            KubeSecretsCredentialsProvider credentialsProvider = KubeSecretsCredentialsProvider.getInstance();
            List<CloudSecrets> secretsForAllClouds = credentialsProvider.getSecretsForAllClouds();
            for (CloudSecrets cloudSecrets : secretsForAllClouds) {
                Domain domain = cloudSecrets.getCredentialsDomain();
                List<ParsedSecret> secrets = cloudSecrets.getSecret();
                LOGGER.fine("Adding " + secrets.size() + " secrets for cloud " + cloudSecrets.getCloud().getDisplayName());
                if (secrets.size() > 0) {
                    credentialsArray.addAll(DomainCredentials.getCredentials(credentialsProvider.getDomainCredentialsMap(), type, domainRequirements, matcher));
                }
            }

            LOGGER.fine("Found " + credentialsArray.size() + " credentials in clouds");
            return credentialsArray;
        }

        @Override
        public String getIconClassName() {
            return "icon-credentials-system-store";
        } // todo
    }

    /**
     * Our management link descriptor.
     */
    @Extension
    @SuppressWarnings("unused") // used by Jenkins
    public static final class DescriptorImpl extends Descriptor<KubeSecretsCredentialsProvider> {
        /**
         * {@inheritDoc}
         */
        @Override
        public String getDisplayName() {
            return "";
        }

    }

    /**
     * Our {@link CredentialsStore}.
     */
    @ExportedBean
    public static class StoreImpl extends CredentialsStore {

        /**
         * Our store action.
         */
        private final KubeSecretsCredentialsProvider.UserFacingAction storeAction = new UserFacingAction();

        public StoreImpl() {
            super(ProviderImpl.class);
        }

        /**
         * {@inheritDoc}
         */
        @NonNull
        @Override
        public ModelObject getContext() {
            return Jenkins.getInstance();
        }

        /**
         * {@inheritDoc}
         */
        @Override
        public boolean hasPermission(@NonNull Authentication a, @NonNull Permission permission) {
            // create/update/delete not implemented yet. perhaps better to leave this?
            if(permission.equals(CredentialsProvider.CREATE) || permission.equals(CredentialsProvider.UPDATE) || permission.equals(CredentialsProvider.DELETE)) {
                return false;
            }

            return getACL().hasPermission(a, permission);
        }

        public ACL getACL() {
            return Jenkins.getInstance().getACL();
        }

        /**
         * {@inheritDoc}
         */
        @NonNull
        @Override
        @Exported
        public List<Domain> getDomains() {
            return Collections.unmodifiableList(new ArrayList<Domain>(
                    KubeSecretsCredentialsProvider.getInstance().getDomainCredentialsMap().keySet()
            ));
        }

        /**
         * {@inheritDoc}
         */
        @NonNull
        @Override
        @Exported
        public List<Credentials> getCredentials(@NonNull Domain domain) {
            return KubeSecretsCredentialsProvider.getInstance().getCredentials(domain);
        }

        /**
         * {@inheritDoc}
         */
        @Override
        public boolean addCredentials(@NonNull Domain domain, @NonNull Credentials credentials) throws IOException {
            return KubeSecretsCredentialsProvider.getInstance().addCredentials(domain, credentials);
        }

        /**
         * {@inheritDoc}
         */
        @Override
        public boolean removeCredentials(@NonNull Domain domain, @NonNull Credentials credentials) throws IOException {
            return KubeSecretsCredentialsProvider.getInstance().removeCredentials(domain, credentials);
        }

        /**
         * {@inheritDoc}
         */
        @Override
        public boolean updateCredentials(@NonNull Domain domain, @NonNull Credentials current,
                                         @NonNull Credentials replacement) throws IOException {
            return KubeSecretsCredentialsProvider.getInstance().updateCredentials(domain, current, replacement);
        }

        /**
         * {@inheritDoc}
         */
        @Nullable
        @Override
        public CredentialsStoreAction getStoreAction() {
            return storeAction;
        }

        /**
         * {@inheritDoc}
         */
        @Override
        public void save() throws IOException {
            throw new IOException("Cannot save kubernetes secret credentials");
        }
    }

    /**
     * Expose the store.
     */
    @ExportedBean
    public static class UserFacingAction extends CredentialsStoreAction {

        /**
         * {@inheritDoc}
         */
        @NonNull
        public CredentialsStore getStore() {
            return KubeSecretsCredentialsProvider.getInstance().getStore();
        }

        /**
         * {@inheritDoc}
         */
        @Override
        public String getIconFileName() {
            return isVisible()
                    ? "/plugin/credentials/images/24x24/system-store.png" // todo
                    : null;
        }

        /**
         * {@inheritDoc}
         */
        @Override
        public String getIconClassName() {
            return isVisible()
                    ? "icon-credentials-system-store" // todo
                    : null;
        }

        /**
         * {@inheritDoc}
         */
        @Override
        public String getDisplayName() {
            return "Kubernetes Secret";
        }
    }
}
