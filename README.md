# kubernetes-secrets

Credentials provider for the credentials that reads Kubernetes secrets.
This allows you to define Kubernetes secrets, and they'll be available as credentials inside Jenkins.

The plugins requires that Jenkins runs inside Kubernetes.

This is a work in progress but the basics have already been achieved.

## Left to do

- Documentation
- Make the following configuration
  - Kubernetes API host/port
  - Secret namespace and name
  - SSL Certificates are currently always disabled. This should be an option.
- Reuse the Kubernetes plugin's cloud configuration.
- Need to add credentials in separate domain per cloud config.
- Clean up
- Write tests

## Note
The code is messy as this was more of a proof of concept. The code needs to be cleaned up and then packaged up.
