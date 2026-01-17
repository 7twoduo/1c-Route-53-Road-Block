resource "aws_ssm_parameter" "port" {
  name        = "port"
  description = "This is the RDS port"
  type        = "SecureString"
  value       = 3306
  tags = {
    environment = "production"
  }
}
resource "aws_ssm_parameter" "host" {
  name        = "host"
  description = "This is the endpoint to the RDS instance"
  type        = "SecureString"
  value       = aws_db_instance.below_the_valley.address
  tags = {
    environment = "production"
  }
}
resource "aws_ssm_parameter" "db_name" {
  name        = "db_name"
  description = "This is the name of the database within the RDS instance"
  type        = "SecureString"
  value       = aws_db_instance.below_the_valley.db_name
  tags = {
    environment = "production"
  }
}

#                                                                     Cloudwatch ALARM
#Cloudwatch Logs to watch database and EC2 for any failures and Alert me
resource "aws_sns_topic" "health_check_topic" {
  name = "ServiceHealthCheckTopic"
}
resource "aws_sns_topic_subscription" "email_subscription" {
  topic_arn = aws_sns_topic.health_check_topic.arn
  protocol  = "email"
  # Replace with your email address
  endpoint = var.sns_email
  #Remember you have to confirm your subscription for this to work
}
#Cloudwatch Log Group
resource "aws_cloudwatch_log_group" "db_logs" {
  name              = "rds/${aws_db_instance.below_the_valley.id}/error"
  retention_in_days = 7 # Set log retention (e.g., 7 days)
}
resource "aws_cloudwatch_log_metric_filter" "connection_failure_filter" {
  name           = "DBConnectionFailureFilter"
  log_group_name = aws_cloudwatch_log_group.db_logs.name
  pattern        = "?ERROR ?FATAL ?CRITICAL ?Connection ?failed"
  # Adjust pattern based on exact error messages in your specific DB engine logs

  metric_transformation {
    name      = "DBConnectionFailureCount"
    namespace = "Custom/RDS"
    value     = "1"
  }
}
resource "aws_cloudwatch_metric_alarm" "below_the_valley_db_alarm01" {
  alarm_name          = "${local.name_prefix}-db-connection-failure"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  metric_name         = "DBConnectionErrors"
  namespace           = "Lab/RDSApp"
  period              = 300
  statistic           = "Sum"
  threshold           = 3
  alarm_actions       = [aws_sns_topic.health_check_topic.arn]
  dimensions = {
    DBInstanceIdentifier = aws_db_instance.below_the_valley.identifier
  }
  tags = {
    Name = "${local.name_prefix}-alarm-db-fail"
  }

  depends_on = [aws_db_instance.below_the_valley]
}
#My Custom Metric for Cloudwatch Database logs
resource "aws_cloudwatch_metric_alarm" "connection_failure_alarm" {
  alarm_name          = "High-DB-Connection-Failure-Rate"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 5
  metric_name         = aws_cloudwatch_log_metric_filter.connection_failure_filter.metric_transformation[0].name
  namespace           = "AWS/RDS"
  period              = 60 # Check every 60 seconds
  statistic           = "Average"
  threshold           = 1 # Trigger if 5 or more failures in the period
  dimensions = {
    DBInstanceIdentifier = aws_db_instance.below_the_valley.identifier
  }
  alarm_description = "The following ${local.terradbname} RDS server is running into connection issues. Check to see what the problem is and if you cannont remedy it, replace it. Replace it in terraform by running -terraform apply -replace ${local.terradbname} (If you have access to the terraform this is the remedy) "
  alarm_actions     = [aws_sns_topic.health_check_topic.arn]

  depends_on = [aws_db_instance.below_the_valley]
}

#This tracks for when the CPU utilization is below 1 percent for more than 5 minutes which means the server is not running
resource "aws_cloudwatch_metric_alarm" "rds-CPUUtilization" {
  alarm_name          = "rds-CPUUtilization"
  comparison_operator = "LessThanOrEqualToThreshold"
  evaluation_periods  = 5
  metric_name         = "CPUUtilization"
  namespace           = "AWS/RDS"
  period              = 60 #Requirements is 5 minutes, so 300 seconds(50s X 2 periods = 100s x3 thresholds = 300s)
  statistic           = "Minimum"
  threshold           = 1
  treat_missing_data  = "breaching"

  dimensions = {
    DBInstanceIdentifier = aws_db_instance.below_the_valley.identifier
  }
  alarm_description = "The following ${local.terradbname} RDS is not running because a running server CPU utilization  doesn't go lower than one. Check to see what the problem is and if you cannont remedy it, replace it. Replace it in terraform by running -terraform apply -replace ${local.terradbname} (If you have access to the terraform this is the remedy) "
  alarm_actions     = [aws_sns_topic.health_check_topic.arn]

  depends_on = [aws_db_instance.below_the_valley]
}

#Use RDS Snapshots to restore RDS in case of failure

#s3 Bucket
resource "aws_s3_bucket" "spire" {
  bucket = var.s3_bucket
  region = var.aws_region

  tags = {
    Name        = "My bucket"
    Environment = "Dev"
  }
}

#S3 Gateway VPC Endpoint for S3 access within the VPC
resource "aws_vpc_endpoint" "s3_gateway_endpoint" {
  vpc_id            = local.vpc_id
  service_name      = "com.amazonaws.${var.aws_region}.s3"
  vpc_endpoint_type = "Gateway"
  route_table_ids   = [aws_route_table.Private.id]
}

# Cloudwatch Endpoint
resource "aws_vpc_endpoint" "logs" {
  vpc_id             = local.vpc_id
  service_name       = "com.amazonaws.${var.aws_region}.logs" # Use the specific service name for CloudWatch Logs
  vpc_endpoint_type  = "Interface"
  subnet_ids         = [aws_subnet.Star_Private_AZ1.id, aws_subnet.Star_Private_AZ2.id]
  security_group_ids = [aws_security_group.EC2_SG.id]

  # Enable private DNS names for the endpoint
  private_dns_enabled = true

  tags = {
    Name = "deathless-god-endpoint-cloudwatch-logs"
  }
}

#Secrets Manager VPC Endpoint
resource "aws_vpc_endpoint" "secrets_manager" {
  vpc_id              = local.vpc_id
  vpc_endpoint_type   = "Interface"
  service_name        = "com.amazonaws.${var.aws_region}.secretsmanager"
  subnet_ids          = [aws_subnet.Star_Private_AZ1.id, aws_subnet.Star_Private_AZ2.id]
  security_group_ids  = [aws_security_group.EC2_SG.id]
  private_dns_enabled = true

  tags = {
    Name = "SecretsManagerVPCEndpoint"
  }
}

# EC2 Messages VPC Endpoint
resource "aws_vpc_endpoint" "ec2messages" {
  # The service name format is "com.amazonaws.<region>.ec2messages"
  service_name      = "com.amazonaws.${var.aws_region}.ec2messages"
  vpc_id            = local.vpc_id
  vpc_endpoint_type = "Interface"
  # Associate the endpoint with your private subnet IDs
  subnet_ids = [aws_subnet.Star_Private_AZ1.id, aws_subnet.Star_Private_AZ2.id]
  # Associate the dedicated security group
  security_group_ids = [aws_security_group.EC2_SG.id]
  # Enable private DNS names for seamless resolution within the VPC
  private_dns_enabled = true

  tags = {
    Name = "EC2Messages VPC Endpoint"
  }
}

# SSM VPC Endpoint
resource "aws_vpc_endpoint" "ssmmessages" {
  vpc_id              = local.vpc_id
  service_name        = "com.amazonaws.${var.aws_region}.ssmmessages"
  vpc_endpoint_type   = "Interface"
  security_group_ids  = [aws_security_group.EC2_SG.id]
  subnet_ids          = [aws_subnet.Star_Private_AZ1.id, aws_subnet.Star_Private_AZ2.id]
  private_dns_enabled = true

  tags = {
    Name = "ssmmessages-endpoint"
  }
}
resource "aws_vpc_endpoint" "ssm" {
  vpc_id              = local.vpc_id
  service_name        = "com.amazonaws.${var.aws_region}.ssm"
  vpc_endpoint_type   = "Interface"
  security_group_ids  = [aws_security_group.EC2_SG.id]
  subnet_ids          = [
    aws_subnet.Star_Private_AZ1.id,
    aws_subnet.Star_Private_AZ2.id
  ]
  private_dns_enabled = true

  tags = {
    Name = "ssm-endpoint"
  }
}


#                            ELITE TIP: USE AWS POLICY GENERATOR SAVES SUFFERING
#S3 Bucket to store ALB logs
resource "aws_s3_bucket_policy" "lb-bucket-policy" {
  bucket = aws_s3_bucket.spire.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowALBAccessLogs"
        Effect = "Allow"

        Principal = {
          Service = "delivery.logs.amazonaws.com"
        }

        Action = "s3:PutObject"

        Resource = "arn:aws:s3:::${aws_s3_bucket.spire.id}/AWSLOGS/${data.aws_caller_identity.current.account_id}"

        Condition = {
          StringEquals = {
            "s3:x-amz-acl"      = "bucket-owner-full-control"
            "aws:SourceAccount" = "${data.aws_caller_identity.current.account_id}"
          }
        }
      }
    ]
  })
}


#                                           Load Balancer
# locals {
#   aws_imported_lb = "LoadExternal"
# }
# data "aws_lb" "existing" {
#   name = local.aws_imported_lb
# }
#                               Comment in when you get the Provider level problem and input the bucket arn if it doesn't get brought in by the data block
# import {
#   to = aws_lb.hidden_alb
#   id = "arn:aws:elasticloadbalancing:us-east-1:915742579869:loadbalancer/app/LoadExternal/96e365f3f968e601"
# }
resource "aws_lb" "hidden_alb" {
  name               = "LoadExternal"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.EC2_SG.id]

  subnets = [
    aws_subnet.Star_Public_AZ1.id,
    aws_subnet.Star_Public_AZ2.id,
  ]
    access_logs {
      bucket  = var.s3_bucket
      prefix  = "AWSLOGS"
      enabled = true
    }
   tags = {
     Name = "App1LoadBalancer"
   }
}

#                                      DOMAIN NAME : ROUTE 53
#############################################################################################
#Target Group for Load Balancer
resource "aws_lb_target_group" "hidden_target_group" {
  name     = "hidden-target-group"
  port     = 80 # You forgot the Port here
  protocol = "HTTP"
  vpc_id   = local.vpc_id

  health_check {
    enabled             = true
    healthy_threshold   = 2
    unhealthy_threshold = 2
    timeout             = 5
    interval            = 30
    path                = "/"
    matcher             = "200-399"
  }

  depends_on = [aws_instance.lab-ec2-app-private]
  tags = {
    Name = "Target Group for hidden target_group"
  }
}
#                                   Listeners for TARGET GROUP


resource "aws_route53_zone" "primary" {
  name = var.root_domain_name
}
resource "aws_acm_certificate" "hidden_target_group2" {
  domain_name       = var.root_domain_name
  validation_method = "DNS"

  tags = {
    Name = "hidden target_group certificate"
  }
}
resource "aws_route53_record" "cert_validation" {
  for_each = (
    var.certificate_validation_method == "DNS" &&
    length(aws_acm_certificate.hidden_target_group2.domain_validation_options) > 0
  ) ? {
    for dvo in aws_acm_certificate.hidden_target_group2.domain_validation_options :
    dvo.domain_name => {
      name   = dvo.resource_record_name
      type   = dvo.resource_record_type
      record = dvo.resource_record_value
    }
  } : {}

  zone_id = aws_route53_zone.primary.zone_id
  name    = each.value.name
  type    = each.value.type
  ttl     = 60
  records = [each.value.record]
}


resource "aws_acm_certificate_validation" "star_cert_validation1" {
  count = var.certificate_validation_method == "DNS" ? 1 : 0
  certificate_arn         = aws_acm_certificate.hidden_target_group2.arn
  validation_record_fqdns = [for r in aws_route53_record.cert_validation : r.fqdn]
}

resource "aws_lb_listener" "http" {
  load_balancer_arn = aws_lb.hidden_alb.arn
  port              = 80
  protocol          = "HTTP"

  default_action {
    type = "redirect"
    redirect {
      port        = "443"
      protocol    = "HTTPS"
      status_code = "HTTP_301"
    }
  }
}
resource "aws_lb_listener" "https" {
  load_balancer_arn = aws_lb.hidden_alb.arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-2021-06"
  certificate_arn   = aws_acm_certificate.hidden_target_group2.arn



  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.hidden_target_group.arn
  }
  depends_on = [aws_acm_certificate_validation.star_cert_validation1]
}
resource "aws_lb_target_group_attachment" "http" {
  target_group_arn = aws_lb_target_group.hidden_target_group.arn
  target_id        = aws_instance.lab-ec2-app-private.id
  port             = 80
  depends_on       = [aws_instance.lab-ec2-app-private]
}


#                                 WAF : Web Application Firewall
resource "aws_wafv2_web_acl" "alb_waf" {
  name        = "alb_waf_defender"
  description = "This is to protect my application load balancer through WAF"
  scope       = "REGIONAL"

  default_action {
    allow {}
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "${var.Environment}-waf01"
    sampled_requests_enabled   = true
  }

  # Explanation: AWS managed rules are like hiring Rebel commandos — they’ve seen every trick.
  rule {
    name     = "AWSManagedRulesCommonRuleSet"
    priority = 1

    override_action {
      none {}
    }

    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesCommonRuleSet"
        vendor_name = "AWS"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "${var.Environment}-waf-common"
      sampled_requests_enabled   = true
    }
  }

  tags = {
    Name = "${var.Environment}-waf01"
  }
}

resource "aws_wafv2_web_acl_association" "chewbacca_waf_assoc01" {
  count = var.enable_waf ? 1 : 0

  resource_arn = aws_lb.hidden_alb.arn
  web_acl_arn  = aws_wafv2_web_acl.alb_waf.arn
}

############################################
# CloudWatch Alarm: ALB 5xx -> SNS
############################################
resource "aws_cloudwatch_metric_alarm" "chewbacca_alb_5xx_alarm01" {
  alarm_name          = "${var.Environment}-alb-5xx-alarm01"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = var.alb_5xx_evaluation_periods
  threshold           = var.alb_5xx_threshold
  period              = var.alb_5xx_period_seconds
  statistic           = "Sum"

  namespace   = "AWS/ApplicationELB"
  metric_name = "HTTPCode_ELB_5XX_Count"

  dimensions = {
    LoadBalancer = aws_lb.hidden_alb.arn_suffix
  }

  alarm_actions = [aws_sns_topic.health_check_topic.arn]

  tags = {
    Name = "${var.Environment}-alb-5xx-alarm01"
  }
}

############################################
# CloudWatch Dashboard (Skeleton)
############################################

# Explanation: Dashboards are your cockpit HUD — Chewbacca wants dials, not vibes.
resource "aws_cloudwatch_dashboard" "chewbacca_dashboard01" {
  dashboard_name = "${var.Environment}-dashboard01"

  # TODO: students can expand widgets; this is a minimal workable skeleton
  dashboard_body = jsonencode({
    widgets = [
      {
        type   = "metric"
        x      = 0
        y      = 0
        width  = 12
        height = 6
        properties = {
          metrics = [
            ["AWS/ApplicationELB", "RequestCount", "LoadBalancer", aws_lb.hidden_alb.arn_suffix],
            [".", "HTTPCode_ELB_5XX_Count", ".", aws_lb.hidden_alb.arn_suffix]
          ]
          period = 300
          stat   = "Sum"
          region = var.aws_region
          title  = "Chewbacca ALB: Requests + 5XX"
        }
      },
      {
        type   = "metric"
        x      = 12
        y      = 0
        width  = 12
        height = 6
        properties = {
          metrics = [
            ["AWS/ApplicationELB", "TargetResponseTime", "LoadBalancer", aws_lb.hidden_alb.arn_suffix]
          ]
          period = 300
          stat   = "Average"
          region = var.aws_region
          title  = "Chewbacca ALB: Target Response Time"
        }
      }
    ]
  })
}
##############################################################################################################################################################################################################
# Explanation: The zone apex is the throne room—chewbacca-growl.com itself should lead to the ALB.
/*
resource "aws_route53_record" "chewbacca_apex_alias01" {
  zone_id = local.chewbacca_zone_id
  name    = var.domain_name
  type    = "A"

  alias {
    name                   = aws_lb.chewbacca_alb01.dns_name
    zone_id                = aws_lb.chewbacca_alb01.zone_id
    evaluate_target_health = true
  }
}

############################################
# S3 bucket for ALB access logs
############################################

# Explanation: This bucket is Chewbacca’s log vault—every visitor to the ALB leaves footprints here.
resource "aws_s3_bucket" "chewbacca_alb_logs_bucket01" {
  count = var.enable_alb_access_logs ? 1 : 0

  bucket = "${var.Environment}-alb-logs-${data.aws_caller_identity.chewbacca_self01.account_id}"

  tags = {
    Name = "${var.Environment}-alb-logs-bucket01"
  }
}

# Explanation: Block public access—Chewbacca does not publish the ship’s black box to the galaxy.
resource "aws_s3_bucket_public_access_block" "chewbacca_alb_logs_pab01" {
  count = var.s3_bucket ? 1 : 0

  bucket                  = aws_s3_bucket.chewbacca_alb_logs_bucket01[0].id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Explanation: Bucket ownership controls prevent log delivery chaos—Chewbacca likes clean chain-of-custody.
resource "aws_s3_bucket_ownership_controls" "chewbacca_alb_logs_owner01" {
  count = var.enable_alb_access_logs ? 1 : 0

  bucket = aws_s3_bucket.chewbacca_alb_logs_bucket01[0].id
  rule {
    object_ownership = "BucketOwnerPreferred"
  }
}

# Explanation: TLS-only—Chewbacca growls at plaintext and throws it out an airlock.
resource "aws_s3_bucket_policy" "chewbacca_alb_logs_policy01" {
  count = var.enable_alb_access_logs ? 1 : 0

  bucket = aws_s3_bucket.chewbacca_alb_logs_bucket01[0].id

  # NOTE: This is a skeleton. Students may need to adjust for region/account specifics.
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "DenyInsecureTransport"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource = [
          aws_s3_bucket.chewbacca_alb_logs_bucket01[0].arn,
          "${aws_s3_bucket.chewbacca_alb_logs_bucket01[0].arn}/*"
        ]
        Condition = {
          Bool = { "aws:SecureTransport" = "false" }
        }
      },
      {
        Sid    = "AllowELBPutObject"
        Effect = "Allow"
        Principal = {
          Service = "elasticloadbalancing.amazonaws.com"
        }
        Action   = "s3:PutObject"
        Resource = "${aws_s3_bucket.chewbacca_alb_logs_bucket01[0].arn}/${var.alb_access_logs_prefix}/AWSLogs/${data.aws_caller_identity.chewbacca_self01.account_id}/*"
      }
    ]
  })
}


#                                 CDN : Content Delivery Network
*/