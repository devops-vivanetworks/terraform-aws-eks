variable "vpc_id" {
    type = string
    description = "The Existing VPC"
}

variable "subnet_ids" {
    type = list(string)
    description = "The Existing Subnets in the existing VPC"
}

#variable "aws_auth_accounts" {
#    type = list(string)
#    description = "AWS Account ID that EKS can Access"
#}

#variable "userarn" {
#    type = string
#    description = "For user that can Access Fargate pods"
#}

#variable "username" {
#    type = string
#    description = "Username for user that can access Fargate pods"
#}

#variable "user_group" {
#    type = list(string)
#    description = "Group of role for user to use the pods"
#}

#variable "rolearn" {
#    type = string
#    description = "ARN role to add to aws configmap"
#}

#variable "roleusername" {
#    type = string
#    description = "Username for role to add to aws configmap"
#}