# k8s install

The stratus k8s operator relies on a token reviewer service account in the cluster. stratus must be able to contact the cluster api to validate the service account token.

`docs/k8s/yaml` has the k8s resources required to create the token reviewer service account and ClusterRoleBinding.

Once the service account is created, you will need to retrieve the k8s api address, ca cert, and token reviewer jwt and store this in Vault. 

```bash
 sa_name=stratus
 cluster_name=homelab
 token_reviewer_jwt=$(kubectl get secret \
    $(kubectl get serviceaccount $sa_name \
      -n kube-system \
      -o jsonpath='{.secrets[0].name}') \
  -n kube-system \
  -o jsonpath='{.data.token}')

  kubernetes_ca_cert=$(kubectl get secret \
    $(kubectl get serviceaccount $sa_name \
      -n kube-system \
      -o jsonpath='{.secrets[0].name}') \
  -n kube-system \
  -o jsonpath='{.data.ca\.crt}')

  kubernetes_host=`kubectl config view | yq e ".clusters[] | select(.name==\"$(kubectl config current-context)\") | .cluster.server" -`
  echo '{"validationToken": "'$token_reviewer_jwt'","clusterHost": "'$kubernetes_host'", "clusterCA": "'$kubernetes_ca_cert'"}' | vault kv put devops/stratus-dev/$cluster_name -
```

## Service Account Usage

To create a service account that can be assumed by another workload identity through stratus, create the SA as usual, and then set the token in vault:

```bash
sa_name=stratus-poc-sa
namepace=stratus-dev
 cluster_name=homelab
 token=$(kubectl get secret \
    $(kubectl get serviceaccount $sa_name \
      -n kube-system \
      -o jsonpath='{.secrets[0].name}') \
  -n kube-system \
  -o jsonpath='{.data.token}')

  kubernetes_ca_cert=$(kubectl get secret \
    $(kubectl get serviceaccount $sa_name \
      -n kube-system \
      -o jsonpath='{.secrets[0].name}') \
  -n kube-system \
  -o jsonpath='{.data.ca\.crt}')

  kubernetes_host=`kubectl config view | yq e ".clusters[] | select(.name==\"$(kubectl config current-context)\") | .cluster.server" -`
  echo '{"jwt": "'$token'","clusterHost": "'$kubernetes_host'", "clusterCA": "'$kubernetes_ca_cert'"}' | vault kv put stratus-dev/system:serviceaccount:$namespace:$sa_name -
```