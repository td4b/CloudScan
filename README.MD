
<div align="center">
<img src="https://github.com/td4b/CloudScan/blob/master/icon.png" width="40%">
</div>

## Description

TBD

## Installation

```bash
kubectl create namespace flux-system
```

```bash
helm install -n flux-system flux oci://ghcr.io/fluxcd-community/charts/flux2
```

Install kustomize if you do not have it already, then deploy the helm charts/ manifests.

```bash
cd kustomize
kustomize build . | kubectl apply -f -
```
