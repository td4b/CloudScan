helm repo add elastic https://helm.elastic.co
helm repo update

helm install elasticsearch elastic/elasticsearch --namespace monitoring -f elasticvalues.yml
#  helm upgrade elasticsearch elastic/elasticsearch --namespace monitoring -f elasticvalues.yml
kubectl create secret generic elastic-credentials \
  --from-literal=username=elastic \
  --from-literal=password=elastic \
  -n monitoring

kubectl get secrets --namespace=monitoring elasticsearch-master-credentials -ojsonpath='{.data.password}' | base64 -d

helm repo add grafana https://grafana.github.io/helm-charts
helm repo update

helm install loki-stack grafana/loki-stack -n monitoring -f lokivalues.yml
# helm upgrade loki-stack grafana/loki-stack -n monitoring -f lokivalues.yml
# helm uninstall loki-stack -n monitoring 

sudo k3s kubectl create configmap external-scan --from-file=dashboard.json -n monitoring
# sudo k3s kubectl delete configmap external-scan -n monitoring
