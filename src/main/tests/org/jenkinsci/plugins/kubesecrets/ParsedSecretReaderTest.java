package org.jenkinsci.plugins.kubesecrets;

import io.fabric8.kubernetes.api.model.ObjectMeta;
import io.fabric8.kubernetes.api.model.Secret;
import org.csanchez.jenkins.plugins.kubernetes.KubernetesCloud;
import org.junit.Test;

import java.util.HashMap;
import java.util.List;

import static org.junit.Assert.*;
import static org.mockito.Mockito.mock;

public class ParsedSecretReaderTest {
    @Test
    public void getConfig() throws Exception {
        KubernetesCloud cloud = mock(KubernetesCloud.class);

        HashMap<String, String> data = new HashMap<>();
        data.put("docker_host_cert_auth_test_clientCertificate", "c29tZWJhc2U2NHZhbHVl");
        data.put("docker_host_cert_auth_test_clientKey", "c29tZWJhc2U2NHZhbHVl");
        data.put("docker_host_cert_auth_test_serverCACertificate", "c29tZWJhc2U2NHZhbHVl");
        data.put("openshift_oauth_token_test_token", "c29tZWJhc2U2NHZhbHVl");
        data.put("openshift_username_password_test_password", "c29tZWJhc2U2NHZhbHVl");
        data.put("secret_text_test_secret", "c29tZWJhc2U2NHZhbHVl");
        data.put("ssh_username_private_key_test_passphrase", "c29tZWJhc2U2NHZhbHVl");
        data.put("ssh_username_private_key_test_private_key", "c29tZWJhc2U2NHZhbHVl");
        data.put("username_password_test_password", "c29tZWJhc2U2NHZhbHVl");


        ObjectMeta objectMeta = mock(ObjectMeta.class);
        Secret secret = new Secret("v1", data, "Secret", objectMeta, null, "Opaque");

        String filePath = "/Users/hosh/Workspace/tesco/aurora-core/kubernetes-secrets/src/main/resources/secrets_config.yaml";


        List<ParsedSecret> parsedSecret = ParsedSecretReader.getConfig(cloud, secret, filePath);

    }

}