provider "aws" {
  region = local.region
}

locals {
  name            = "tvlk-eks-using-fargate"
  cluster_version = "1.22"
  region          = "ap-southeast-1"

  tags = {
    Example    = local.name
    GithubRepo = "terraform-aws-eks"
    GithubOrg  = "Traveloka"
  }
}

module "eks" {
  source = "../.."

  cluster_name                    = local.name
  cluster_version                 = local.cluster_version
  cluster_endpoint_private_access = true
  cluster_endpoint_public_access  = true


  vpc_id                        = var.vpc_id
  subnet_ids                    = var.subnet_ids
  cluster_enabled_log_types     = ["api", "audit", "authenticator", "controllerManager", "scheduler"]

  aws_auth_fargate_profile_pod_execution_role_arns = [aws_iam_role.epe.name]

  // Fargate profiles here
  fargate_profiles = {
    coredns-fargate-profile = {
      name = "coredns"
      selectors = [
        {
          namespace = "kube-system"
          labels = {
            k8s-app = "kube-dns"
          }
        },
        {
          namespace = "default"
        }
      ]
      subnet_ids = var.subnet_ids
    }
  }
}

####### Add-ons resources#####

resource "aws_iam_role" "epe"{
    name = "eks-fargate-pod-execution"

    assume_role_policy = jsonencode({
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        Service = "eks-fargate-pods.amazonaws.com"
      }
    }]
    Version = "2012-10-17"
  })
}