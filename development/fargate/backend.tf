terraform {
  backend "s3" {
    bucket         = "default-terraform-state-ap-southeast-1-460124681500"
    dynamodb_table = "tvlk-terraform-aws-eks-fargate"
    key            = "aws-eks/tsi-dev-fargate/terraform.tfstate"
    region         = "ap-southeast-1"
    encrypt        = "true"
  }
}