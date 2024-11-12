
<div align="center">
<img src="https://github.com/td4b/CloudScan/blob/master/icon.png" width="40%">
</div>

## Description

This is a red team information gathering and network enumeration tool used to visualize results from Subfinder and Nuclei against a set of predefined target domains.

## Configuration

Input your API keys for the Nuclei scanning engine under `kustomize/releases/scanner/yaml` as well as the target domains.

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: subfinder-config
  namespace: monitoring  # Change to your namespace if different
data:
  provider-config.yaml: |
    # Your configuration here
    virustotal:
      - API_KEY

    shodan:
      - API_KEY
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: cloudscan-config
  namespace: monitoring
data:
  config.toml: |
    # Example configuration settings
    [settings]
    targets = ["domain.com"]
```

## Installation/ Deployment

This system is designed to operate on a Kubernettes cluster, I used k3s as my distribution of choice. 

```bash
kubectl create namespace flux-system
```

```bash
helm install -n flux-system flux oci://ghcr.io/fluxcd-community/charts/flux2
```

Install kustomize if you do not have it already, then deploy the helm charts/ manifests.

```bash
cd kustomize
kubectl create namespace monitoring
kustomize build . | kubectl apply -f -
```

Get the grafana secret to login/ view dashboards.

```bash
kubectl get secret --namespace monitoring grafana -o jsonpath="{.data.admin-password}" | base64 --decode ; echo
```
