terraform {
  required_providers {
    helm = {
      source  = "hashicorp/helm"
      version = "3.3.0"
    }
  }
}

provider "helm" {
  kubernetes = {
    host     = "https://127.0.0.1:6443"
    token    = "offline-plan-probe-not-a-secret"
    insecure = true
  }
}

resource "helm_release" "r" {
  name      = "probe"
  chart     = "${path.module}/chart"
  namespace = "probe"
}
