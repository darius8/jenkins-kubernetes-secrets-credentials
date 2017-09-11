package org.jenkinsci.plugins.kubesecrets;

import hudson.Extension;
import jenkins.model.GlobalConfiguration;
import org.jenkinsci.Symbol;

import javax.annotation.CheckForNull;
import javax.annotation.Nonnull;
import java.util.logging.Logger;

@Extension
@Symbol("location")
public class KubernetesSecretConfig extends GlobalConfiguration {
    private String configMapName;
    private String secretName;

    /**
     * Gets local configuration.
     *
     * @return {@code null} if the {@link GlobalConfiguration#all()} list does not contain this extension.
     * Most likely it means that the Jenkins instance has not been fully loaded yet.
     */
    @CheckForNull
    public static KubernetesSecretConfig get() {
        return GlobalConfiguration.all().get(KubernetesSecretConfig.class);
    }

    public KubernetesSecretConfig() {
        load();
    }

    @Nonnull
    public String getConfigMapName() {
        return configMapName == null ? "" : configMapName;
    }

    @Nonnull
    public String getSecretName() {
        return secretName == null ? "" : secretName;
    }

    public void setConfigMapName(@CheckForNull String configMapName) {
        this.configMapName = configMapName;
        save();
    }

    public void setSecretName(@CheckForNull String secretName) {
        this.secretName = secretName;
        save();
    }
}
