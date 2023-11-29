.PHONY: all build-webapi build-pullworker build-scanworker

all: build-webapi build-pullworker build-scanworker

build-webapi:
	go build -o ./bin/webapi ./cmd/webapi

build-pullworker:
	go build -o ./bin/pull_worker ./cmd/pullworker

build-scanworker:
	go build -o ./bin/scan_worker ./cmd/scanworker

k8s-webapi-portforward:
	kubectl port-forward svc/webapi 8080:8080
k8s-deploy:
	kubectl apply -f k8s/registry/registry-deployment.yaml
	kubectl apply -f k8s/registry/registry-service.yaml
	kubectl apply -f k8s/redis/redis-deployment.yaml
	kubectl apply -f k8s/redis/redis-service.yaml
	kubectl apply -f k8s/volumes/shared-reports-pvc.yaml
	kubectl apply -f k8s/webapi/webapi-deployment.yaml
	kubectl apply -f k8s/webapi/webapi-service.yaml
	kubectl apply -f k8s/scanworker/scanworker-deployment.yaml
	kubectl apply -f k8s/pullworker/pullworker-deployment.yaml
	kubectl apply -f k8s/pullworker/pushworker-deployment.yaml


k8s-build-images:
	docker-compose build

k8s-tag-images: k8s-build-images
	docker tag trivy_runner_scanworker localhost:5000/trivy_runner_scanworker:latest
	docker tag trivy_runner_pushworker localhost:5000/trivy_runner_pushworker:latest
	docker tag trivy_runner_pullworker localhost:5000/trivy_runner_pullworker:latest
	docker tag trivy_runner_webapi localhost:5000/trivy_runner_webapi:latest

k8s-push-images: k8s-tag-images
	docker push localhost:5000/trivy_runner_scanworker:latest
	docker push localhost:5000/trivy_runner_pullworker:latest
	docker push localhost:5000/trivy_runner_pushworker:latest
	docker push localhost:5000/trivy_runner_webapi:latest

lint:
	docker run --rm -v "$(CURDIR):/app" -w /app golangci/golangci-lint:v1.55.2 golangci-lint run -v


