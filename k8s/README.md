# NetScope Kubernetes Deployment

These manifests deploy NetScope to a Kubernetes cluster in the `netscope`
namespace. The application image must already be available to the cluster
as `netscope:local`.

## 1. Create the namespace

kubectl apply -f k8s/namespace.yaml
