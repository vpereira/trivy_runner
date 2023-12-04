.PHONY: all webapi pullworker scanworker pushworker

all: webapi pullworker scanworker pushworker

webapi:
	go build -o ./bin/webapi ./cmd/webapi

pullworker:
	go build -o ./bin/pull_worker ./cmd/pullworker

scanworker:
	go build -o ./bin/scan_worker ./cmd/scanworker

pushworker:
	go build -o ./bin/push_worker ./cmd/pushworker

integration-server:
	-docker network create shared_network
	docker-compose -f docker-compose.yml -f docker-compose-integration.yml up

k8s-webapi-portforward:
	kubectl port-forward svc/webapi 8080:8080

k8s-deploy:
	kubectl apply -f k8s/registry/registry-deployment.yaml
	kubectl apply -f k8s/registry/registry-service.yaml
	kubectl apply -f k8s/redis/redis-deployment.yaml
	kubectl apply -f k8s/redis/redis-service.yaml
	kubectl apply -f k8s/volumes/shared-reports-pvc.yaml
	kubectl apply -f k8s/volumes/shared-reports-pv.yaml
	kubectl apply -f k8s/webapi/webapi-deployment.yaml
	kubectl apply -f k8s/webapi/webapi-service.yaml
	kubectl apply -f k8s/scanworker/scanworker-deployment.yaml
	kubectl apply -f k8s/pullworker/pullworker-deployment.yaml
	kubectl apply -f k8s/pullworker/pushworker-deployment.yaml


k8s-build-images:
	docker-compose build

k8s-tag-images: k8s-build-images
	docker tag trivy_runner-scanworker localhost:5000/trivy_runner_scanworker:latest
	docker tag trivy_runner-pushworker localhost:5000/trivy_runner_pushworker:latest
	docker tag trivy_runner-pullworker localhost:5000/trivy_runner_pullworker:latest
	docker tag trivy_runner-webapi localhost:5000/trivy_runner_webapi:latest

k8s-push-images: k8s-tag-images
	docker push localhost:5000/trivy_runner_scanworker:latest
	docker push localhost:5000/trivy_runner_pullworker:latest
	docker push localhost:5000/trivy_runner_pushworker:latest
	docker push localhost:5000/trivy_runner_webapi:latest

lint:
	docker run --rm -v "$(CURDIR):/app" -w /app golangci/golangci-lint:v1.55.2 golangci-lint run -v


