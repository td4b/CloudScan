#!/bin/bash 

# Function to check metrics server health
check_metrics_server_health() {
  echo "Checking metrics server API health..."
  for i in {1..10}; do
    if kubectl get apiservices v1beta1.metrics.k8s.io | grep -q True; then
      echo "Metrics server API is healthy."
      return 0
    fi
    echo "Waiting for metrics server API to become healthy... Attempt $i/10"
    sleep 10
  done
  echo "Metrics server API is not healthy after 10 attempts. Exiting."
  exit 1
}

echo "Waiting for the cluster to be ready..."
kubectl wait --for=condition=ready nodes --all --timeout=120s

# Check if metrics server is healthy
check_metrics_server_health

echo "Creating FLux system namespace."
kubectl create namespace flux-system

echo "Installing Flux CRDs."
helm install flux oci://ghcr.io/fluxcd-community/charts/flux2

echo "Creating monitoring namespace."
kubectl create namespace monitoring

echo "Installing Elastic and Grafana charts."
kustomize build ../kustomize | kubectl apply -f -
echo "Done setting up Virtual Machine."
