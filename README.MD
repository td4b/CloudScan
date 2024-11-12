
<div align="center">
<img src="https://github.com/td4b/CloudScan/blob/master/icon.png" width="40%">
</div>

## Description

This is a red team information gathering and network enumeration tool used to visualize results from Subfinder and Nuclei against a set of predefined target domains.

## Configuration

Input your API keys for the Subfinder domain scanning engine under the default location: `~/.config/subfinder/`

For the target domains set them here: `ingest/config.toml`.

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

## Running the Scans

After numerous testing I have found that Nuclei does not play well running inside a k8s cluster for mass scanning operations. The best results will come from running the binary directly on the host machine so it has direct access to the host and networking resources.

`Note: Even running the container with hostnetwork specs only marginally improved the scanning results.`

```bash
cd ingest/
go build main.go
./main
```

## Dashboards

You should be able to view the dashboard for Grafana via port forwarding the grafana pod (replace with your actual POD).

`kubectl port-forward grafana-6647577557-cbzks 3000:3000 -n monitoring`

<div align="center">
<img src="https://github.com/td4b/CloudScan/blob/master/dashboard.png" width="100%">
</div>
