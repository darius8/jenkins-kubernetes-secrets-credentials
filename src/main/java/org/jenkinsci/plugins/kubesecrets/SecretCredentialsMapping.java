package org.jenkinsci.plugins.kubesecrets;

import com.cloudbees.jenkins.plugins.sshcredentials.impl.BasicSSHUserPrivateKey;
import com.cloudbees.jenkins.plugins.sshcredentials.impl.BasicSSHUserPrivateKey.DirectEntryPrivateKeySource;
import com.cloudbees.plugins.credentials.Credentials;
import com.cloudbees.plugins.credentials.CredentialsScope;
import com.cloudbees.plugins.credentials.impl.UsernamePasswordCredentialsImpl;
import hudson.util.Secret;
import org.jenkinsci.plugins.plaincredentials.impl.StringCredentialsImpl;

import java.util.Map;

//import org.csanchez.jenkins.plugins.kubernetes.ServiceAccountCredential;

class SecretCredentialsMapping {
    static Credentials createCredentialsFromSecret(ParsedSecret parsedSecret) {

        return null;
        // todo it has to be possible to do this neater.
//        switch (data.get("type")) {
//            case "usernamewithpassword":
//                return getUsernamePasswordCredentials(id, data);
//            case "sshusernameprivsecretkey":
//                return getBasicSSHUserPrivateKey(id, data);
//            case "secrtext":
//                return getSecretTextCredentials(id, data);
//            case "kubernetesserviceaccount":
//                return getServiceAccountCredential(id, data);
//            default:
//                throw new RuntimeException("Credential type " + data.get("type") + " has not been implemented yet.");
//        }
    }

    private static Credentials getSecretTextCredentials(String id, Map<String, String> data) {
        return new StringCredentialsImpl(
                CredentialsScope.GLOBAL,
                id,
                data.get("description"),
                Secret.fromString(data.get("value"))
        );
    }

    private static Credentials getServiceAccountCredential(String id, Map<String, String> data) {
        return null;
//        return new ServiceAccountCredential(
//                CredentialsScope.GLOBAL,
//                id,
//                data.get("description")
//        );
    }
}
