# The parent instance that hosts the enclave.
#
# What this brings up is deliberately the *untrusted* half: a machine, a
# network path to it, and permission to read the buckets. The enclave's
# identity comes from PCR0, which is a property of the image rather than of
# anything declared here — so nothing in this file needs to be trusted for the
# attestation argument to hold, and none of it is a place to put a secret.
#
#   nix build .#eif && packer build … deploy/ami     # → ami-…
#   tofu init && tofu apply -var ami_id=ami-…
#
# Storage is out of scope on purpose. The roots bucket carries Object Lock
# COMPLIANCE retention, which cannot be shortened or removed by anyone,
# including AWS support; creating that from a general-purpose deployment is a
# way to lose a bucket for ten years by typo. Point this at buckets that
# already exist.

terraform {
  required_version = ">= 1.6"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region  = var.region
  profile = var.aws_profile
}

locals {
  name = "${var.name_prefix}-${var.environment}"

  tags = {
    Name        = local.name
    Environment = var.environment
    Component   = "nitro-enclave-parent"
    ManagedBy   = "opentofu"
  }
}

# ---------------------------------------------------------------------------
# Network
# ---------------------------------------------------------------------------

resource "aws_vpc" "this" {
  cidr_block           = var.vpc_cidr
  enable_dns_support   = true
  enable_dns_hostnames = true
  tags                 = local.tags
}

resource "aws_internet_gateway" "this" {
  vpc_id = aws_vpc.this.id
  tags   = local.tags
}

resource "aws_subnet" "public" {
  vpc_id                  = aws_vpc.this.id
  cidr_block              = var.subnet_cidr
  availability_zone       = var.availability_zone
  map_public_ip_on_launch = true
  tags                    = local.tags
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.this.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.this.id
  }

  tags = local.tags
}

resource "aws_route_table_association" "public" {
  subnet_id      = aws_subnet.public.id
  route_table_id = aws_route_table.public.id
}

# ---------------------------------------------------------------------------
# Access
# ---------------------------------------------------------------------------

resource "aws_security_group" "enclave" {
  name        = "${local.name}-enclave"
  description = "Inbound HTTPS to the enclave; egress for S3, KMS and ACME"
  vpc_id      = aws_vpc.this.id
  tags        = local.tags

  # TLS terminates *inside* the enclave, so what passes through here is
  # ciphertext the parent cannot read. This rule admits traffic to the machine;
  # it does not grant the machine sight of it.
  ingress {
    description = "HTTPS, terminated inside the enclave"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = var.ingress_cidrs
  }

  # Services that share the parent and are no part of the enclave — they see
  # only what reaches them, like anything else on the parent.
  dynamic "ingress" {
    for_each = var.extra_ingress_ports
    content {
      description = "Beside the enclave, on the parent"
      from_port   = ingress.value
      to_port     = ingress.value
      protocol    = "tcp"
      cidr_blocks = var.ingress_cidrs
    }
  }

  # No SSH. Nothing here is meant to be reached by hand, and an open shell on
  # the parent is the most useful thing an attacker could be given — it is the
  # machine that proxies every byte in and out of the enclave. Use SSM if a
  # session is genuinely needed.
  egress {
    description = "Outbound for S3, KMS and the ACME provider"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# ---------------------------------------------------------------------------
# Identity
# ---------------------------------------------------------------------------

resource "aws_iam_role" "parent" {
  name = "${local.name}-parent"
  tags = local.tags

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Action    = "sts:AssumeRole"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
}

# The parent proxies the enclave's S3 traffic, so its role is what reaches the
# buckets. That is not a hole in the design: the objects are encrypted under
# keys derived from a master secret the parent does not hold, so this grants
# the ability to serve and delete ciphertext, not to read it.
data "aws_iam_policy_document" "buckets" {
  statement {
    sid    = "ReadWriteObjects"
    effect = "Allow"
    actions = [
      "s3:GetObject",
      "s3:PutObject",
      "s3:DeleteObject",
      "s3:ListBucket",
      "s3:GetBucketLocation",
      # Root records are read by version, underneath any delete marker.
      "s3:ListBucketVersions",
      "s3:GetObjectVersion",
      # A PutObject that carries retention headers needs this too.
      "s3:PutObjectRetention",
    ]
    resources = concat(
      ["arn:aws:s3:::${var.roots_bucket}"],
      ["arn:aws:s3:::${var.roots_bucket}/*"],
    )
  }

  # The anchor chain is what makes rollback detectable, and Object Lock is what
  # makes it immutable. Nothing on the parent has any business relaxing that,
  # so the permission to do it is withheld rather than merely unused.
  # PutObjectRetention is not in this list because the runtime needs it to
  # write roots at all, and in COMPLIANCE mode it can only extend a retention,
  # never shorten one.
  statement {
    sid    = "NeverWeakenRetention"
    effect = "Deny"
    actions = [
      "s3:PutBucketObjectLockConfiguration",
      "s3:PutObjectLegalHold",
      "s3:BypassGovernanceRetention",
    ]
    resources = ["*"]
  }
}

resource "aws_iam_role_policy" "buckets" {
  name   = "${local.name}-buckets"
  role   = aws_iam_role.parent.id
  policy = data.aws_iam_policy_document.buckets.json
}

# ---------------------------------------------------------------------------
# Guest logs
# ---------------------------------------------------------------------------

# For building log ARNs by hand — see the policy below.
data "aws_caller_identity" "current" {}

# Created here, not by the enclave. The enclave holds `logs:PutLogEvents` and
# nothing more, so a compromised or misconfigured image cannot create log
# groups — and a typo in the group name fails its boot loudly instead of
# quietly filling a new group nobody is watching.
resource "aws_cloudwatch_log_group" "guest" {
  name = "/${local.name}/guest"

  # Set deliberately. Left unset these never expire, and the contents are
  # attacker-controlled: whatever a guest chose to write to stdout. An
  # unbounded retention on unbounded input is an unbounded bill.
  retention_in_days = var.guest_log_retention_days

  tags = local.tags
}

resource "aws_cloudwatch_log_stream" "guest" {
  name           = "guest"
  log_group_name = aws_cloudwatch_log_group.guest.name
}

# This is the **parent instance's** role, and it is the identity that will make
# the call. The enclave is not an IAM principal and has none of its own: it has
# no NIC, so its SDK reaches IMDS through gvproxy on this instance and receives
# these credentials. When the enclave gets an attested identity of its own,
# this statement moves there and the parent stops being able to write to the
# stream at all.
data "aws_iam_policy_document" "guest_logs" {
  statement {
    sid     = "WriteGuestLogs"
    effect  = "Allow"
    actions = ["logs:PutLogEvents"]
    # The one stream, not the group and not `*`. Nothing here needs to create
    # a group, a stream, or write to anyone else's.
    #
    # Built from components rather than from `aws_cloudwatch_log_group.arn`,
    # which is inconsistent about carrying a trailing `:*`. Appending to it
    # would silently produce an ARN matching nothing — and the symptom is an
    # `AccessDeniedException`, which this runtime treats as a deployment
    # mistake and refuses to boot on. Worth the extra interpolation.
    resources = [
      "arn:aws:logs:${var.region}:${data.aws_caller_identity.current.account_id}:log-group:${aws_cloudwatch_log_group.guest.name}:log-stream:${aws_cloudwatch_log_stream.guest.name}",
    ]
  }
}

resource "aws_iam_role_policy" "guest_logs" {
  name   = "${local.name}-guest-logs"
  role   = aws_iam_role.parent.id
  policy = data.aws_iam_policy_document.guest_logs.json
}

# Wake signals, through the one push application the image names (`pushAppId` in
# deploy/nix/deployment.nix) and nothing else: sending, and reading its FCM channel, which the
# runtime does once at boot to refuse an application that could never deliver. The Firebase
# credential lives on that channel, not here and not in the image. None without an application.
data "aws_iam_policy_document" "push" {
  count = var.push_app_id == "" ? 0 : 1
  statement {
    sid     = "SendWakes"
    effect  = "Allow"
    actions = ["mobiletargeting:SendMessages", "mobiletargeting:GetGcmChannel"]
    resources = [
      "arn:aws:mobiletargeting:${var.region}:${data.aws_caller_identity.current.account_id}:apps/${var.push_app_id}",
      "arn:aws:mobiletargeting:${var.region}:${data.aws_caller_identity.current.account_id}:apps/${var.push_app_id}/*",
    ]
  }
}

resource "aws_iam_role_policy" "push" {
  count  = var.push_app_id == "" ? 0 : 1
  name   = "${local.name}-push"
  role   = aws_iam_role.parent.id
  policy = data.aws_iam_policy_document.push[0].json
}

# Guest telemetry, as the image names it (`xray` and `metricsNamespace` in
# deploy/nix/deployment.nix), and only what the runtime calls. X-Ray takes no
# resource-level scoping, so trace segments are account-wide; metrics are held to the
# image's one namespace by condition. Nothing when telemetry is off.
locals {
  telemetry_on = var.telemetry.xray || var.telemetry.metrics_namespace != ""
}

data "aws_iam_policy_document" "telemetry" {
  count = local.telemetry_on ? 1 : 0

  dynamic "statement" {
    for_each = var.telemetry.xray ? [1] : []
    content {
      sid       = "PutGuestTraces"
      effect    = "Allow"
      actions   = ["xray:PutTraceSegments"]
      resources = ["*"]
    }
  }

  dynamic "statement" {
    for_each = var.telemetry.metrics_namespace != "" ? [1] : []
    content {
      sid       = "PutGuestMetrics"
      effect    = "Allow"
      actions   = ["cloudwatch:PutMetricData"]
      resources = ["*"]
      condition {
        test     = "StringEquals"
        variable = "cloudwatch:namespace"
        values   = [var.telemetry.metrics_namespace]
      }
    }
  }
}

resource "aws_iam_role_policy" "telemetry" {
  count  = local.telemetry_on ? 1 : 0
  name   = "${local.name}-telemetry"
  role   = aws_iam_role.parent.id
  policy = data.aws_iam_policy_document.telemetry[0].json
}

# ---------------------------------------------------------------------------
# Background tasks
# ---------------------------------------------------------------------------

# Where a guest's background tasks are recorded, scheduled and delivered
# (runtime/src/tasks). EventBridge Scheduler fires each task into the queue;
# the enclave receives it, checks it against its record here, and runs it. An
# operator sees every task — its state, its next run, how its last run went —
# in the table.
#
# The parent's role reaches all of it, so none of it is trusted on its own:
# every task is signed with a key derived from its tenant's key, its payload is
# sealed to the same key, and a delivery before its time is dropped. What the
# parent can still do here is delete or delay, which it can always do.

resource "aws_dynamodb_table" "tasks" {
  name         = "${local.name}-tasks"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "pk"
  range_key    = "sk"

  attribute {
    name = "pk"
    type = "S"
  }
  attribute {
    name = "sk"
    type = "S"
  }
  attribute {
    name = "state_key"
    type = "S"
  }
  attribute {
    name = "updated_at"
    type = "N"
  }

  # "Which tasks are scheduling, cancelling, scheduled": for the runtime's
  # reconciler, and for an operator.
  global_secondary_index {
    name            = "by-state"
    hash_key        = "state_key"
    range_key       = "updated_at"
    projection_type = "ALL"
  }

  # Each run's record expires thirty days after its last write.
  ttl {
    attribute_name = "expires_at"
    enabled        = true
  }

  tags = local.tags
}

# Where a message goes that the enclave keeps receiving and never finishes —
# one whose run brings the enclave down. Kept for the longest SQS allows.
resource "aws_sqs_queue" "tasks_dead" {
  name                      = "${local.name}-tasks-dead"
  message_retention_seconds = 1209600
  sqs_managed_sse_enabled   = true
  tags                      = local.tags
}

resource "aws_sqs_queue" "tasks" {
  name = "${local.name}-tasks"
  # Past an attempt's ten minutes and the record after it. The runtime sets it
  # on every receive as well.
  visibility_timeout_seconds = 900
  # A due task waits this long for an enclave that is down: four days.
  message_retention_seconds = 345600
  receive_wait_time_seconds = 20
  sqs_managed_sse_enabled   = true
  # High enough that a tenant busy for a while, or a few retries, never trips
  # it: an attempt the enclave died in is counted by the runtime itself.
  redrive_policy = jsonencode({
    deadLetterTargetArn = aws_sqs_queue.tasks_dead.arn
    maxReceiveCount     = 50
  })
  tags = local.tags
}

resource "aws_scheduler_schedule_group" "tasks" {
  name = "${local.name}-tasks"
  tags = local.tags
}

# The role EventBridge Scheduler takes to put a firing on the queue: that, and
# nothing else, for schedules in this account.
resource "aws_iam_role" "scheduler" {
  name = "${local.name}-scheduler"
  tags = local.tags

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Action    = "sts:AssumeRole"
      Principal = { Service = "scheduler.amazonaws.com" }
      Condition = {
        StringEquals = { "aws:SourceAccount" = data.aws_caller_identity.current.account_id }
      }
    }]
  })
}

resource "aws_iam_role_policy" "scheduler" {
  name = "${local.name}-scheduler"
  role = aws_iam_role.scheduler.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = "sqs:SendMessage"
      Resource = aws_sqs_queue.tasks.arn
    }]
  })
}

# What the runtime calls, on these resources only. SendMessage too: a task due
# within fifteen minutes goes straight on the queue, delayed, and one that came
# due while its owner was away is sent again when they sign in.
data "aws_iam_policy_document" "tasks" {
  statement {
    sid    = "RecordTasks"
    effect = "Allow"
    actions = [
      "dynamodb:GetItem",
      "dynamodb:PutItem",
      "dynamodb:DeleteItem",
      "dynamodb:Query",
    ]
    resources = [
      aws_dynamodb_table.tasks.arn,
      "${aws_dynamodb_table.tasks.arn}/index/by-state",
    ]
  }

  statement {
    sid    = "ScheduleTasks"
    effect = "Allow"
    actions = [
      "scheduler:CreateSchedule",
      "scheduler:DeleteSchedule",
      "scheduler:GetSchedule",
    ]
    resources = [
      "arn:aws:scheduler:${var.region}:${data.aws_caller_identity.current.account_id}:schedule/${aws_scheduler_schedule_group.tasks.name}/*",
    ]
  }

  statement {
    sid       = "HandSchedulesTheirRole"
    effect    = "Allow"
    actions   = ["iam:PassRole"]
    resources = [aws_iam_role.scheduler.arn]
    condition {
      test     = "StringEquals"
      variable = "iam:PassedToService"
      values   = ["scheduler.amazonaws.com"]
    }
  }

  statement {
    sid    = "ReceiveTasks"
    effect = "Allow"
    actions = [
      "sqs:ReceiveMessage",
      "sqs:DeleteMessage",
      "sqs:ChangeMessageVisibility",
      "sqs:SendMessage",
    ]
    resources = [aws_sqs_queue.tasks.arn]
  }
}

resource "aws_iam_role_policy" "tasks" {
  name   = "${local.name}-tasks"
  role   = aws_iam_role.parent.id
  policy = data.aws_iam_policy_document.tasks.json
}

# Seen in the console; attach actions to page someone.
resource "aws_cloudwatch_metric_alarm" "tasks_dead" {
  alarm_name          = "${local.name}-tasks-dead"
  alarm_description   = "A task message the enclave kept receiving and never finished was set aside."
  namespace           = "AWS/SQS"
  metric_name         = "ApproximateNumberOfMessagesVisible"
  dimensions          = { QueueName = aws_sqs_queue.tasks_dead.name }
  statistic           = "Maximum"
  period              = 300
  evaluation_periods  = 1
  threshold           = 0
  comparison_operator = "GreaterThanThreshold"
  treat_missing_data  = "notBreaching"
  tags                = local.tags
}

resource "aws_cloudwatch_metric_alarm" "tasks_waiting" {
  alarm_name          = "${local.name}-tasks-waiting"
  alarm_description   = "Due tasks have waited over half an hour: the enclave is down, or cannot keep up."
  namespace           = "AWS/SQS"
  metric_name         = "ApproximateAgeOfOldestMessage"
  dimensions          = { QueueName = aws_sqs_queue.tasks.name }
  statistic           = "Maximum"
  period              = 300
  evaluation_periods  = 3
  threshold           = 1800
  comparison_operator = "GreaterThanThreshold"
  treat_missing_data  = "notBreaching"
  tags                = local.tags
}

# For a shell without opening port 22.
resource "aws_iam_role_policy_attachment" "ssm" {
  role       = aws_iam_role.parent.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_instance_profile" "parent" {
  name = "${local.name}-parent"
  role = aws_iam_role.parent.name
  tags = local.tags
}

# ---------------------------------------------------------------------------
# The instance
# ---------------------------------------------------------------------------

resource "aws_instance" "parent" {
  ami                    = var.ami_id
  instance_type          = var.instance_type
  subnet_id              = aws_subnet.public.id
  vpc_security_group_ids = [aws_security_group.enclave.id]
  iam_instance_profile   = aws_iam_instance_profile.parent.name

  # The whole point of the machine. Without it `nitro-cli run-enclave` fails
  # with a message about the driver rather than about this flag.
  enclave_options {
    enabled = true
  }

  # Nitro Enclaves needs at least 4 vCPUs, because the allocator reserves whole
  # cores for the enclave and the parent still has to run. Smaller types are
  # accepted by the API and then cannot start an enclave.
  lifecycle {
    precondition {
      condition     = can(regex("\\.(x|2x|4x|8x|12x|16x|24x|metal)large$", var.instance_type)) || can(regex("\\.xlarge$", var.instance_type))
      error_message = "instance_type must be enclave-capable with >= 4 vCPUs (xlarge or bigger)."
    }
  }

  root_block_device {
    volume_size = 32
    volume_type = "gp3"
    encrypted   = true
  }

  metadata_options {
    http_tokens   = "required" # IMDSv2
    http_endpoint = "enabled"

    # UNVERIFIED ON HARDWARE. The enclave reaches IMDS only at 192.168.127.253,
    # which gvproxy maps to 169.254.169.254 (deploy/ami/units/gvproxy.yml) and
    # the image names in AWS_EC2_METADATA_SERVICE_ENDPOINT; no guest can reach
    # it. Every AWS call the enclave makes rests on that path, and the QEMU
    # harness has no metadata service to prove it with. The push probe at boot
    # is the first check that it works.
    #
    # One hop is right: gvproxy proxies rather than routes — it terminates the
    # enclave's connection here and dials its own (pkg/services/forwarder/tcp.go),
    # so the request originates on this instance. Stated rather than defaulted,
    # because the value is a deployment decision and not an incidental.
    http_put_response_hop_limit = 1
  }

  # Which device is the pool's disk: the one thing the parent needs that the
  # image cannot know. The enclave's settings are in the image, measured.
  user_data = templatefile("${path.module}/user-data.sh.tftpl", {
    # How the volume appears to the parent: NVMe, named by its id.
    pool_disk = "/dev/disk/by-id/nvme-Amazon_Elastic_Block_Store_${replace(aws_ebs_volume.pool.id, "-", "")}"
  })

  user_data_replace_on_change = true

  tags = local.tags
}

# ---------------------------------------------------------------------------
# The pool's disk
# ---------------------------------------------------------------------------

# Where everything the enclave keeps lives: a ZFS pool on dm-crypt, served to
# the enclave by nbdkit on the parent (deploy/ami/units/nbdkit.service). The
# parent sees only ciphertext; the anchor chain in the roots bucket is what
# makes a rolled-back or substituted volume refused at boot — restoring an
# older snapshot of this volume is exactly that, and the enclave will not
# serve it.
#
# Never destroyed by a plan: this volume *is* the state. Losing it leaves
# anchors no disk can satisfy, and the enclave refuses to start rather than
# begin again.
resource "aws_ebs_volume" "pool" {
  availability_zone = aws_subnet.public.availability_zone
  size              = var.pool_size_gib
  type              = "gp3"
  # Amazon's at-rest encryption, beneath the enclave's own dm-crypt.
  encrypted = true

  lifecycle {
    prevent_destroy = true
  }

  tags = merge(local.tags, { Name = "${local.name}-pool" })
}

resource "aws_volume_attachment" "pool" {
  device_name = "/dev/sdf"
  volume_id   = aws_ebs_volume.pool.id
  instance_id = aws_instance.parent.id
}
