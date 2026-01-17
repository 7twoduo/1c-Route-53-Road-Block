#Provider configuration
terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
    }
    tls = {
      source  = "hashicorp/tls"
    }
    local = {
      source = "hashicorp/local"
    }
    random = {
      source = "hashicorp/random"
    }
  }
}

provider "aws" {
  region = "us-east-1"
}


terraform {
  backend "local" {
    path = "secrets/terraform.tfstate"
  }
}

#VPC Resource
resource "aws_vpc" "Star" {
  cidr_block           = var.vpc_cidr
  instance_tenancy     = "default"
  enable_dns_hostnames = true
  enable_dns_support   = true


  tags = {
    Name = "Star_VPC"
  }
}


#Public Subnet in AZ1
resource "aws_subnet" "Star_Public_AZ1" {
  vpc_id                  = aws_vpc.Star.id
  cidr_block              = var.public_subnet_cidr1
  availability_zone       = "us-east-1a"
  map_public_ip_on_launch = true

  tags = {
    Name = "Star_Public_AZ1"
  }
}
resource "aws_subnet" "Star_Public_AZ2" {
  vpc_id                  = aws_vpc.Star.id
  cidr_block              = var.public_subnet_cidr2
  availability_zone       = "us-east-1b"
  map_public_ip_on_launch = true

  tags = {
    Name = "Star_Public_AZ2"
  }
}


#Private Subnet in AZ1
resource "aws_subnet" "Star_Private_AZ1" {
  vpc_id            = aws_vpc.Star.id
  cidr_block        = var.private_subnet_cidr1
  availability_zone = "us-east-1a"

  tags = {
    Name = "Star_Private_AZ1"
  }
}
resource "aws_subnet" "Star_Private_AZ2" {
  vpc_id            = aws_vpc.Star.id
  cidr_block        = var.private_subnet_cidr2
  availability_zone = "us-east-1b"

  tags = {
    Name = "Star_Private_AZ2"
  }
}
#Internet Gateway
resource "aws_internet_gateway" "internet" {
  vpc_id = aws_vpc.Star.id

  tags = {
    Name = "Star_IGW"
  }
}
resource "aws_eip" "nat" {
  tags = {
    Name = "Star_NAT_EIP"
  }
}
#NAT Gateway
resource "aws_nat_gateway" "nat_gateway" {
  allocation_id = aws_eip.nat.id
  subnet_id     = aws_subnet.Star_Public_AZ1.id
  depends_on    = [aws_eip.nat]

  tags = {
    Name = "Star_NAT_GW"
  }
}
resource "aws_route_table" "Public" {
  vpc_id = aws_vpc.Star.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.internet.id
  }
}
# resource "aws_route_table" "Private" {
#   vpc_id = aws_vpc.Star.id
#   route {
#     cidr_block = "0.0.0.0/0"
#     gateway_id = "local" # Change to S3 Gateway Endpoint later
#   }
# }
resource "aws_route_table" "Private" {
  vpc_id = aws_vpc.Star.id
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_nat_gateway.nat_gateway.id # Change to S3 Gateway Endpoint later
  }
}
resource "aws_route_table_association" "Known" {
  for_each = {
    uno = aws_subnet.Star_Public_AZ1.id
    dos = aws_subnet.Star_Public_AZ2.id
  }
  subnet_id      = each.value
  route_table_id = aws_route_table.Public.id
}

resource "aws_route_table_association" "Secret" {
  for_each = {
    uno = aws_subnet.Star_Private_AZ1.id
    dos = aws_subnet.Star_Private_AZ2.id
  }
  subnet_id      = each.value
  route_table_id = aws_route_table.Private.id
}
#Security Group
resource "aws_security_group" "RDS_SG" {
  name        = "RDS_SG"
  description = "Allow TLS inbound traffic from EC2_SG and outbound traffic to EC2_SG"
  vpc_id      = aws_vpc.Star.id

  tags = {
    Name = "RDS_SG"
  }
}
resource "aws_security_group" "EC2_SG" {
  name        = "EC2_SG"
  description = "Allow TLS inbound traffic on HTTP and RDP and all outbound traffic"
  vpc_id      = aws_vpc.Star.id

  tags = {
    Name = "EC2_SG"
  }
}
resource "aws_vpc_security_group_ingress_rule" "allow_http_ipv4" {
  security_group_id = aws_security_group.EC2_SG.id
  cidr_ipv4         = var.public_access_cidr
  from_port         = 80
  ip_protocol       = "tcp"
  to_port           = 80
}
resource "aws_vpc_security_group_ingress_rule" "allow_https_ipv4" {
  security_group_id = aws_security_group.EC2_SG.id
  cidr_ipv4         = var.public_access_cidr
  from_port         = 443
  ip_protocol       = "tcp"
  to_port           = 443
}
resource "aws_vpc_security_group_ingress_rule" "RDS_EC2_SG" {
  security_group_id            = aws_security_group.RDS_SG.id
  referenced_security_group_id = local.EC2_SG_Traffic
  from_port                    = 3306
  ip_protocol                  = "tcp"
  to_port                      = 3306
}
resource "aws_vpc_security_group_ingress_rule" "allow_mysql_ipv4" {
  security_group_id = aws_security_group.EC2_SG.id
  cidr_ipv4         = var.public_access_cidr
  from_port         = 3306
  ip_protocol       = "tcp"
  to_port           = 3306
}

resource "aws_vpc_security_group_egress_rule" "allow_all_egress_ipv4" {
  security_group_id = aws_security_group.EC2_SG.id
  cidr_ipv4         = var.public_access_cidr
  ip_protocol       = "-1" # semantically equivalent to all ports
}

#Secret Manager to store RDS Credentials
resource "random_password" "master" {
  length           = 16
  special          = true
  override_special = "_!%^"
}

#The Big Boy, RDS MySQL Instance
resource "aws_db_subnet_group" "my_db_subnet_group" {
  name       = "my-db-subnet-group"
  subnet_ids = [aws_subnet.Star_Private_AZ1.id, aws_subnet.Star_Private_AZ2.id]

  tags = {
    Name = "My DB subnet group"
  }
}
resource "aws_db_instance" "below_the_valley" {
  allocated_storage               = 10
  db_name                         = "labdb"
  engine                          = "mysql"
  engine_version                  = "8.0.43"
  instance_class                  = "db.t3.micro"
  username                        = var.db_username
  password                        = random_password.master.result
  parameter_group_name            = "default.mysql8.0"
  skip_final_snapshot             = true
  vpc_security_group_ids          = [aws_security_group.RDS_SG.id]
  db_subnet_group_name            = aws_db_subnet_group.my_db_subnet_group.name
  enabled_cloudwatch_logs_exports = ["error"]

  tags = {
    Name      = "My_RDS_Instance"
    terraname = "aws_db_instance.below_the_valley"
  }
}

resource "aws_secretsmanager_secret" "password" {
  name        = var.secret_location
  description = "RDS MySQL credentials for EC2 app"
}
resource "aws_secretsmanager_secret_version" "passwords" {
  secret_id = aws_secretsmanager_secret.password.id
  secret_string = jsonencode({
    username = var.db_username
    password = random_password.master.result
    port     = 3306
    host     = aws_db_instance.below_the_valley.address # Modification mistake cost me 6 hours of troubleshooting(Crazy Time Consumer)
    db_name  = aws_db_instance.below_the_valley.db_name
  })

}
#                                                      EC2 Blocks
#Identy and Access Management Role for EC2 to access RDS
resource "aws_iam_role" "EC2_Role" {
  name = "EC2_Role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Sid    = ""
        Principal = {
          Service = "ec2.amazonaws.com"
        }
      },
    ]
  })

  tags = {
    tag-key = "tag-value"
  }
}

# IF you want stronger Controls use this policy instead of SecretsManagerReadWrite
resource "aws_iam_policy" "secretsmanager_read_policy" {
  name        = "test_policy"
  path        = "/"
  description = "My test policy"
  policy = jsonencode({
    "Version" : "2012-10-17",
    "Statement" : [
      {
        "Sid" : "ReadSpecificSecret",
        "Effect" : "Allow",
        "Action" : ["secretsmanager:GetSecretValue"],
        "Resource" : "arn:aws:secretsmanager:${var.aws_region}:${local.account_id}:secret:${var.secret_location}"
      }
    ]
  })
}
resource "aws_iam_policy" "parameter_store_secrets" {
  name        = "${var.Environment}-lp-ssm-read01"
  description = "Least-privilege read for SSM Parameter Store under /lab/db/*"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "ReadLabDbParams"
        Effect = "Allow"
        Action = [
          "ssm:GetParameter",
          "ssm:GetParameters",
          "ssm:GetParametersByPath"
        ]
        Resource = [
          "arn:aws:ssm:${var.aws_region}:${local.account_id}:parameter/*"
        ]
      }
    ]
  })
}
resource "aws_iam_policy" "cloudwatch_least_priviege" {
  name        = "${var.Environment}-lp-cwlogs01"
  description = "Least-privilege CloudWatch Logs write for the app log group"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "WriteLogs"
        Effect = "Allow"
        Action = [
          "logs:CreateLogStream",
          "logs:PutLogEvents",
          "logs:DescribeLogStreams"
        ]
        Resource = [
          "${aws_cloudwatch_log_group.db_logs.arn}:*"
        ]
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "example_attachment" {
  role = aws_iam_role.EC2_Role.name
  # Secrets Manager Read Access to allow access to RDS credentials
  policy_arn = aws_iam_policy.cloudwatch_least_priviege.arn
}
resource "aws_iam_role_policy_attachment" "example_attachment4" {
  role = aws_iam_role.EC2_Role.name
  # Secrets Manager Read Access to allow access to RDS credentials
  policy_arn = aws_iam_policy.secretsmanager_read_policy.arn
}
resource "aws_iam_role_policy_attachment" "example_attachment3" {
  role = aws_iam_role.EC2_Role.name
  # Secrets Manager Read Access to allow access to RDS credentials
  policy_arn = aws_iam_policy.parameter_store_secrets.arn
}
resource "aws_iam_role_policy_attachment" "example_attachment2" {
  role = aws_iam_role.EC2_Role.name
  # SSM Managed Instance Core to allow SSM Session Manager access
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}
#Associate the EC2 Instance with the Role to access the DB
#Solution to EC2-RDS profile already exist

resource "aws_iam_instance_profile" "this" {

  name = var.ec2_instance_profile_name
  role = aws_iam_role.EC2_Role.name
}

#                                            EC2 Instances Public & Private

resource "aws_instance" "lab-ec2-app-public" {
  ami                         = data.aws_ami.amazon_linux.id
  instance_type               = "t3.micro"
  subnet_id                   = aws_subnet.Star_Public_AZ1.id
  security_groups             = [aws_security_group.EC2_SG.id]
  associate_public_ip_address = true
  user_data_base64            = base64encode(file("userdata.sh"))
  iam_instance_profile        = aws_iam_instance_profile.this.name # Associate the IAM instance profile


  tags = {
    Name = "lab-ec2-app"
  }
}
#Snapshot for Golden AMI Free Tier Eligible

resource "aws_ami_from_instance" "ec2_golden_ami" {
  name               = "ec2-golden-ami"
  source_instance_id = aws_instance.lab-ec2-app-public.id

  depends_on = [
    aws_instance.lab-ec2-app-public
  ]
}

#Use this data block to retriev the AMI ID Once it's created instaed of calling the creation resource directly
data "aws_ami" "ec2_golden_ami" {
  most_recent = true
  owners      = ["self"]

  filter {
    name   = "name"
    values = ["ec2-golden-ami"]
  }

  filter {
    name   = "state"
    values = ["available"]
  }
   depends_on = [aws_ami_from_instance.ec2_golden_ami]
}
#EC2 Instance in Private Subnet from Golden AMI
resource "aws_instance" "lab-ec2-app-private" {
  ami                         = data.aws_ami.ec2_golden_ami.id
  instance_type               = "t3.micro"
  subnet_id                   = aws_subnet.Star_Private_AZ1.id
  security_groups             = [aws_security_group.EC2_SG.id]
  associate_public_ip_address = false
  iam_instance_profile        = aws_iam_instance_profile.this.name
  tags = {
    Name = "lab-ec2-app-private"
  }
  depends_on = [data.aws_ami.ec2_golden_ami]
}


