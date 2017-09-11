package org.jenkinsci.plugins.kubesecrets;

import io.fabric8.kubernetes.api.model.ConfigMap;
import io.fabric8.kubernetes.api.model.Secret;
import org.csanchez.jenkins.plugins.kubernetes.KubernetesCloud;
import org.yaml.snakeyaml.Yaml;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateEncodingException;
import java.util.Base64;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.logging.Logger;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static org.apache.commons.io.Charsets.UTF_8;

public class ParsedSecretReader {
    private static final Logger LOGGER = Logger.getLogger(ParsedSecretReader.class.getName());

    public static List<ParsedSecret> getConfig(
            KubernetesCloud cloud,
            Secret secret,
            String filePathOrConfigMapName
    ) throws UnrecoverableKeyException, CertificateEncodingException, NoSuchAlgorithmException, KeyStoreException, IOException {
        File file = new File(filePathOrConfigMapName);

        String configYaml = null;
        if (file.isFile() && file.canRead()) {
            configYaml = readFromFile(file);
        } else {
            String[] configMapNameAndDataKey = filePathOrConfigMapName.split("\\.");
            if (configMapNameAndDataKey.length == 2) {
                configYaml = readFromConfigMap(cloud, configMapNameAndDataKey[0], configMapNameAndDataKey[1]);
            }
        }

        if (configYaml != null) {
            return parseConfig(configYaml, secret);
        }

        throw new RuntimeException(
                filePathOrConfigMapName + " is neither a config reference or a file. Set \"Config Location\" " +
                        "to a valid readable file or point it to a config in the format \"configMapName.dataKeyName\""
        );
    }

    private static String readFromConfigMap(
            KubernetesCloud cloud,
            String configMapName,
            String dataKey
    ) throws UnrecoverableKeyException, CertificateEncodingException, NoSuchAlgorithmException, KeyStoreException, IOException {
        ConfigMap configMap = cloud.connect()
                .configMaps()
                .inNamespace(cloud.getNamespace())
                .withName(configMapName)
                .get();

        return configMap.getData().get(dataKey);
    }

    private static String readFromFile(File file) throws IOException {
        return new String(Files.readAllBytes(file.toPath()));
    }

    private static List<ParsedSecret> parseConfig(String configYaml, Secret kubeSecrets) {
        Yaml yaml = new Yaml();

        Map<String, List<Map<String, Object>>> config = (Map<String, List<Map<String, Object>>>) yaml.load(configYaml);
        List<Map<String, Object>> secretsObjects = config.get("secrets");

        List<ParsedSecret> parsedSecrets = new LinkedList<>();
        for (Map<String, Object> secretObject : secretsObjects) {
            try {
                parsedSecrets.add(new ParsedSecret(
                        (String) secretObject.get("id"),
                        (String) secretObject.get("kind"),
                        (String) secretObject.get("description"),
                        mapSecretKeyRef(kubeSecrets.getData(), (Map<String, String>) secretObject.get("secretKeyRef"))
                ));
            } catch (IllegalArgumentException e) {
                LOGGER.warning("Could not convert Kubernetes secret to Jenkins credential");
                e.printStackTrace();
            }
        }

        return parsedSecrets;
    }

    private static Map<String, hudson.util.Secret> mapSecretKeyRef(
            Map<String, String> secrets,
            Map<String, String> secretKeyRefs
    ) {
        return secretKeyRefs.entrySet().stream()
                .collect(Collectors.toMap(
                        Map.Entry::getKey,
                        entry -> {
                            String base64String = secrets.get(entry.getValue());

                            if (base64String == null) {
                                return hudson.util.Secret.fromString("");
                            }

                            byte[] decoded = Base64.getDecoder().decode(base64String);
                            String decodedString = new String(decoded, UTF_8);

                            return hudson.util.Secret.fromString(decodedString);
                        }
                ));
    }
}
