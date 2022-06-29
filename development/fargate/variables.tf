variable "vpc_id" {
    type = string
    description = "The Existing VPC"
}

variable "subnet_ids" {
    type = list(string)
    description = "The Existing Subnets in the existing VPC"
}