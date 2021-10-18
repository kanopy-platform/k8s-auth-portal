# k8s-auth-portal

OIDC auth portal for Kubernetes clusters.


## minikube Installation

Push image to local repository

    make minikube

Create helm release

    helm upgrade --install \
    --namespace kube-system \
    --values=./environments/minikube.yaml \
    auth mongodb/web-app

Access app via https://auth.example.com

Uninstall app

    helm uninstall auth --namespace kube-system
