package org.jenkinsci.plugins.kubesecrets;

import hudson.Extension;
import hudson.XmlFile;
import hudson.util.XStream2;
import jenkins.model.GlobalConfiguration;
import jenkins.model.Jenkins;
import org.jenkinsci.Symbol;

import javax.annotation.CheckForNull;
import javax.annotation.Nonnull;
import java.io.File;
import java.io.IOException;
import java.util.logging.Level;
import java.util.logging.Logger;

// todo why is this not showing up inside global config?
@Extension
@Symbol("location")
public class KubernetesSecretConfig extends GlobalConfiguration {
    private String configMapName;
    private String secretName;

    private static final Logger LOGGER = Logger.getLogger(KubernetesSecretConfig.class.getName());

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

    @Override
    public synchronized void load() {
        // for backward compatibility, if we don't have our own data yet, then
        // load from Mailer.
        XmlFile file = getConfigFile();
        if (!file.exists()) {
            XStream2 xs = new XStream2();
            file = new XmlFile(xs, new File(Jenkins.getInstance().getRootDir(), "hudson.tasks.Mailer.xml"));
            if (file.exists()) {
                try {
                    file.unmarshal(this);
                } catch (IOException e) {
                    LOGGER.log(Level.WARNING, "Failed to load " + file, e);
                }
            }
        } else {
            super.load();
        }
    }


    @Nonnull
    public String getConfigMapName() {
        return configMapName;
    }

    @Nonnull
    public String getSecretName() {
        return secretName;
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
