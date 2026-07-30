# Makefile — kubegauge-agent dev loop on kind (build → load → deploy, pushing to the host API).
KIND_CLUSTER ?= kubegauge-dev
IMAGE_REPO   ?= kubegauge-agent
IMAGE_TAG    ?= dev
NAMESPACE    ?= kubegauge
# http is fine here and ONLY here: the deploy below passes allowInsecureHttp=true explicitly, which
# the agent refuses to assume. A real install must use https.
INGEST_URL   ?= http://host.docker.internal:8080

.PHONY: kind-up agent-dev agent-logs

kind-up: ## creates the dev kind cluster if absent
	kind get clusters 2>/dev/null | grep -qx $(KIND_CLUSTER) || kind create cluster --name $(KIND_CLUSTER)

agent-dev: kind-up ## image build + kind load + chart (re)deploy pushing to the host API
	@test -n "$(KG_API_KEY)" || { echo "erro: exporte KG_API_KEY (rode 'make seed' no platform e copie o export)"; exit 1; }
	docker build -t $(IMAGE_REPO):$(IMAGE_TAG) .
	kind load docker-image $(IMAGE_REPO):$(IMAGE_TAG) --name $(KIND_CLUSTER)
	helm upgrade --install kubegauge-agent charts/kubegauge-agent \
		--namespace $(NAMESPACE) --create-namespace \
		--set image.repository=$(IMAGE_REPO) \
		--set image.tag=$(IMAGE_TAG) \
		--set image.pullPolicy=Never \
		--set clusterName=$(KIND_CLUSTER) \
		--set ingestUrl=$(INGEST_URL) \
		--set allowInsecureHttp=true \
		--set apiKey=$(KG_API_KEY)
	kubectl -n $(NAMESPACE) rollout restart deployment/kubegauge-agent
	kubectl -n $(NAMESPACE) rollout status deployment/kubegauge-agent --timeout=180s

agent-logs: ## follow agent logs
	kubectl -n $(NAMESPACE) logs deploy/kubegauge-agent -f
