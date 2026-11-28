# The deployment the e2e boots: `packages.eif-qemu`, and `packages.eif`, the
# same settings under the production binary, which `nix build .#eif --rebuild`
# checks reproduces. Its values are the e2e's own: MinIO's `e2e-roots` bucket,
# a store thrown away after every run.
#
# A real deployment keeps a file of this shape with its own infrastructure and
# builds its image from it:
#
#   packages.x86_64-linux.eif = enclave-runtime.lib.x86_64-linux.mkEif (import ./deployment.nix);
#
# Everything here is baked into the image, so PCR0 covers it, and that is the
# point: **changing any value here changes PCR0**. Two deployments are two
# images, a KMS key policy pinned to one will not release to the other, and
# clients pin different measurements. The enclave's identity includes what it
# operates on.
{
  # The deployment's name, which names every AWS resource it uses, by one rule
  # its infrastructure must follow:
  #
  #   <name>-roots                    the Object-Locked roots bucket, made
  #                                   before the deployment and kept after it
  #   alias/<name>/<release id>       each release's KMS key, the release id
  #                                   being sha256(pcr0 ‖ pcr16)
  #   /<name>/master-key/…            each release's sealed master secret (SSM)
  #   /<name>/operator-master         the operator's master (SSM SecureString)
  #   /<name>/guest                   the guest output log group
  #   <name>                          the guest metrics namespace
  #   <name>-tasks, <name>-scheduler  the background tasks' table, queue and
  #                                   schedule group, and the scheduler's role
  #
  # 1-50 lowercase letters, digits and hyphens.
  name = "e2e";

  # A key prefix inside the roots bucket. Empty for a bucket of its own.
  bucketPrefix = "";

  # 32 hex characters: the HKDF salt, so two filesystems under one master
  # secret stay independent. Not a secret, and supplied rather than read from
  # the store: the keys that verify a root record derive from it, so taking it
  # from the store would mean trusting the store to say which key checks its
  # own signature.
  fsId = "00000000000000000000000000000000";

  region = "us-east-1";

  # The AWS account's 12 digits, which the task queue's URL and the scheduler
  # role's ARN carry. Needed only with `tasks`.
  accountId = "";

  # This runtime release's number. Bump it with every release and never reuse
  # one: a pool last written by a higher number is refused.
  release = 1;

  # How long each root record is locked against deletion, in seconds (Object
  # Lock, COMPLIANCE: nobody can shorten it, AWS support included). It is the
  # horizon of the rollback guarantee, and how long the roots bucket outlives
  # the deployment. The runtime's default is a week; a deployment that holds
  # real value sets longer, and a test deployment says a day, the least the
  # runtime accepts, so it can be retired.
  rootRetentionSecs = 86400;

  # Guest stdout and stderr to CloudWatch as well as the console, in the
  # `/<name>/guest` group's `guest` stream, which the deployment creates. The
  # e2e has no CloudWatch: its credentials are MinIO's.
  guestLogs = false;

  # Guest telemetry (wit/telemetry): each guest invocation to X-Ray as one
  # trace attributed to its tenant, and guest metrics to CloudWatch under the
  # `<name>` namespace. Each needs the instance role's grant.
  xray = false;
  metrics = false;

  # Background tasks through AWS, for a guest that exports `run-task`: the
  # `<name>-tasks` table, queue and schedule group, and the `<name>-scheduler`
  # role, which the deployment creates. Off, a production enclave runs no
  # background tasks, and a testing one (the e2e's) holds them in memory.
  tasks = false;

  # The AWS End User Messaging Push application wake signals go through, or ""
  # for none. Its FCM channel holds the Firebase credential, so the image
  # carries no secret: the runtime signs as the instance's role. The e2e's
  # goes to a stub on the host instead.
  pushAppId = "e2e";

  # The guest is not here. The runtime fetches it from `guest/guest.wasm` in
  # the roots bucket and measures it into PCR16 before it asks KMS for a key,
  # so changing the guest is an upload and a new key, not a new image. Its own
  # settings travel inside its file (`tests/qemu/guest-env.py`) and are
  # measured with it.
}
