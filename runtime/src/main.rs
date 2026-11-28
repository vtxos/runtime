//! `enclave-runtime` — run a Wasm guest over its tenants' ZFS datasets, inside an AWS Nitro
//! Enclave.
//!
//! An enclave has no shell, no config file, and no command line: its image runs this binary with
//! no arguments, in an environment baked into the image's ramdisk and measured into PCR0 with
//! everything else. So **every setting is an environment variable, and nothing else** — and
//! changing one means building a new image, exactly as changing a constant does. That is why
//! there are so few: a setting exists only where two deployments of the same code need different
//! values. Everything else is a constant here.
//!
//! The guest component is **not** in the image. The runtime fetches it at boot from
//! [`GUEST_OBJECT`] in the roots bucket, then measures it into PCR16 and locks that register
//! before it asks KMS for anything — see [`enclave_runtime::guest`]. The guest's own settings
//! travel inside its file and are measured with it — see [`enclave_runtime::env`].
//!
//! The master secret comes from KMS, which releases it only against an attestation whose PCR0
//! and PCR16 match the key policy. The emulator's alternatives — a static key, unsigned receipts,
//! the host's clock, a local object store — are [`Testing`] settings, compiled into `testing`
//! builds alone, so no setting can talk a production binary into any of them.
//!
//! Settings and startup over [`enclave_runtime`], which is the same crate: the library half is
//! everything below this file, and lives beside it rather than inside it so integration tests
//! can reach it.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context as _, Result};
use enclave_runtime::{
    open_clock, open_entropy, parse_bool_flag, serve_component, ClockSource, GuestEnvironment,
    GuestSource, MasterKeySourceKind, MountConfig, NetworkConfig, NetworkMode, RandomSource,
    ServeConfig, DEFAULT_NSM_DEVICE, DEFAULT_PTP_DEVICE, EXIT_RUNTIME_FAILURE,
};

/// Where the guest is, in the roots bucket.
const GUEST_OBJECT: &str = "guest/guest.wasm";

/// Every interface, on 443. Inside an enclave the only interface is the one the parent's proxy
/// reaches, and 443 is where it forwards.
const HTTP_LISTEN: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 443);

/// The stream within the deployment's `/<name>/guest` group.
const GUEST_LOG_STREAM: &str = "guest";

/// How long one S3 request may take, before the SDK's retries.
const S3_TIMEOUT: Duration = Duration::from_secs(30);

/// The deployment name in the KMS encryption context. It was a setting; it stays in the context,
/// with the value every deployment had, so the keys sealed under it still open. The filesystem
/// id is what tells deployments apart.
const KMS_ENVIRONMENT: &str = "production";

/// Notification settings, as far as they can be decided without I/O.
struct NotifySettings {
    app_id: String,
    endpoint: Option<String>,
}

/// A setting's value, with empty meaning unset: the image environment is layered, and setting a
/// variable to "" is how a layer says "not this one".
fn nonempty(value: &Option<String>) -> Option<String> {
    value
        .as_deref()
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .map(str::to_string)
}

/// Start shipping guest spans to X-Ray and guest metrics to CloudWatch, as the flags ask.
///
/// A malformed namespace fails the boot: it is a deployment mistake that would otherwise surface
/// only as every metric refused. A client that cannot be built in time does not: that guest
/// telemetry stays on the console, and the enclave serves.
async fn start_telemetry(
    settings: &Settings,
    image: Option<String>,
) -> Result<enclave_runtime::telemetry::Telemetry> {
    use enclave_runtime::telemetry::{
        CloudWatchMetrics, Metrics, MetricsConfig, Telemetry, Tracer, XrayConfig, XrayDestination,
    };

    let tracer = if settings.xray {
        let config = XrayConfig {
            region: settings.region.clone(),
            endpoint: settings.testing.xray_endpoint.clone(),
        };
        match tokio::time::timeout(
            enclave_runtime::STARTUP_PROBE_TIMEOUT,
            XrayDestination::connect(&config),
        )
        .await
        {
            Ok(destination) => {
                tracing::info!("guest spans are going to X-Ray");
                Some(Tracer::start(
                    std::sync::Arc::new(destination),
                    image,
                    settings.region.clone(),
                ))
            }
            Err(_) => {
                tracing::error!(
                    timeout = ?enclave_runtime::STARTUP_PROBE_TIMEOUT,
                    "could not build an X-Ray client in time; guest spans stay on the console"
                );
                None
            }
        }
    } else {
        None
    };

    let metrics = match settings.metrics.then(|| settings.name.clone()) {
        None => None,
        Some(namespace) => {
            anyhow::ensure!(
                MetricsConfig::valid_namespace(&namespace),
                "ENCLAVE_NAME must make a CloudWatch namespace: 1-255 printable ASCII characters"
            );
            let config = MetricsConfig {
                namespace: namespace.clone(),
                region: settings.region.clone(),
                endpoint: settings.testing.metrics_endpoint.clone(),
            };
            match tokio::time::timeout(
                enclave_runtime::STARTUP_PROBE_TIMEOUT,
                CloudWatchMetrics::connect(&config),
            )
            .await
            {
                Ok(destination) => {
                    tracing::info!(%namespace, "guest metrics are going to CloudWatch");
                    Some(Metrics::start(std::sync::Arc::new(destination), namespace))
                }
                Err(_) => {
                    tracing::error!(
                        timeout = ?enclave_runtime::STARTUP_PROBE_TIMEOUT,
                        %namespace,
                        "could not build a CloudWatch client in time; guest metrics are dropped"
                    );
                    None
                }
            }
        }
    };

    Ok(Telemetry::new(tracer, metrics))
}

/// Under a day of retention protects nothing worth the name.
const MIN_ROOT_RETENTION_SECS: u64 = 86_400;

/// The variable a setting is read from: `prefix` and the field's name in capitals.
fn variable(prefix: &str, field: &str) -> String {
    format!("{prefix}{}", field.to_ascii_uppercase())
}

/// Read a setting from the variable its field's name gives ([`variable`]), bound under that same
/// name. The struct is built from those bindings, so a field and its variable cannot drift apart.
/// `aws` reads the AWS SDK's own `AWS_` name instead of `ENCLAVE_`.
macro_rules! read {
    ($env:ident, aws $field:ident: $how:ident($($arg:expr),*)) => {
        let $field = $env.$how(&variable("AWS_", stringify!($field)) $(, $arg)*)?;
    };
    ($env:ident, $field:ident: $how:ident($($arg:expr),*)) => {
        let $field = $env.$how(&variable("ENCLAVE_", stringify!($field)) $(, $arg)*)?;
    };
}

/// Where settings are read from: the process environment in the enclave, a map in the tests.
struct Env<'a>(&'a dyn Fn(&str) -> Option<String>);

impl Env<'_> {
    /// Set and not empty, or the boot stops.
    fn required(&self, name: &str) -> Result<String> {
        (self.0)(name)
            .filter(|value| !value.trim().is_empty())
            .with_context(|| format!("{name} is not set"))
    }

    /// The value as the image wrote it, empty included: what empty means is each setting's
    /// own rule ([`nonempty`]).
    fn optional(&self, name: &str) -> Result<Option<String>> {
        Ok((self.0)(name))
    }

    fn or(&self, name: &str, default: &str) -> Result<String> {
        Ok((self.0)(name).unwrap_or_else(|| default.to_string()))
    }

    /// `1`/`0`, `true`/`false`, `yes`/`no`, `on`/`off` ([`parse_bool_flag`]); unset is off.
    fn flag(&self, name: &str) -> Result<bool> {
        self.parsed(name, false, parse_bool_flag)
    }

    /// Read with `parse`, or `default` when unset.
    fn parsed<T>(
        &self,
        name: &str,
        default: T,
        parse: fn(&str) -> std::result::Result<T, String>,
    ) -> Result<T> {
        match (self.0)(name) {
            None => Ok(default),
            Some(value) => parse(&value).map_err(|e| anyhow::anyhow!("{name}={value:?}: {e}")),
        }
    }

    /// A whole number, or `default` when unset; with no default, unset stops the boot.
    fn number(&self, name: &str, default: Option<u64>) -> Result<u64> {
        match ((self.0)(name), default) {
            (Some(value), _) => value
                .trim()
                .parse()
                .with_context(|| format!("{name}={value:?} is not a whole number")),
            (None, Some(default)) => Ok(default),
            (None, None) => anyhow::bail!("{name} is not set"),
        }
    }
}

/// The runtime's settings, read once at startup from its environment.
///
/// An enclave has no command line: its image runs `/enclave-runtime` with no arguments, in the
/// environment the image sets. So that environment is the only input, and the tests read it the
/// same way, by name ([`Settings::from_env`]).
///
/// Each field is read from the variable its name gives ([`variable`]): `ENCLAVE_` and the name in
/// capitals, so `name` is `ENCLAVE_NAME`, and the AWS SDK's own settings under its `AWS_` names
/// (`region` is `AWS_REGION`). A value that is wrong stops the boot, naming its variable.
///
/// The AWS resources are not settings: the deployment's [`name`](Settings::name) names them all,
/// by one rule its infrastructure follows, so a setting cannot point one somewhere else.
struct Settings {
    /// The deployment's name, which names every AWS resource it uses: the Object-Locked
    /// `<name>-roots` bucket, the KMS keys under `alias/<name>/`, the SSM parameters under
    /// `/<name>/`, the `/<name>/guest` log group, the `<name>` metrics namespace, and the
    /// `<name>-tasks` table, queue and schedule group with the `<name>-scheduler` role. Required:
    /// 1-50 lowercase letters, digits and hyphens, which every one of those names accepts.
    name: String,

    /// Key prefix inside the roots bucket, so deployments can share one locked bucket.
    bucket_prefix: String,

    /// The filesystem's identifier, 32 hex characters — the key-derivation
    /// salt, so two filesystems under one master secret stay independent.
    ///
    /// Supplied rather than read from the store: the keys that verify a root
    /// record derive from it, so taking it from the store would mean trusting
    /// the store to say which key checks its own signature.
    id: String,

    /// This runtime release's number, written into every anchor it publishes.
    /// A pool last written by a higher number is refused, so an operator
    /// cannot boot an older approved image onto state a newer one has moved
    /// on. Bump it with every release and never reuse one. Required in a
    /// production build; a testing build is release 1 unless told otherwise.
    release: u64,

    /// How long each anchor and boot record is locked against deletion, in seconds.
    ///
    /// COMPLIANCE retention: nobody can shorten it, so the rollback guarantee
    /// lasts this long and so does the roots bucket. A week unless the image
    /// says otherwise; a test deployment may say a day, so it can be retired.
    /// PCR0 therefore tells a client which kind it is talking to. Under a day
    /// is refused: it protects nothing worth the name.
    root_retention_secs: u64,

    /// The AWS region, `AWS_REGION`.
    region: String,

    /// The AWS account's 12 digits, which the task queue's URL and the scheduler role's ARN
    /// carry. Needed only with [`tasks`](Settings::tasks).
    account_id: Option<String>,

    /// The push application wake signals go through: an AWS End User Messaging Push
    /// application, whose FCM channel holds the Firebase credential.
    ///
    /// Empty means notifications are off, so an image can carry the setting and a
    /// deployment can blank it. The image names the application and nothing else:
    /// requests are signed as the instance's own role, so there is no credential
    /// here to set, or to leak from a published image.
    push_app_id: Option<String>,

    /// Guest output to CloudWatch as well as the console: the `guest` stream of the
    /// `/<name>/guest` group, which the deployment creates.
    guest_logs: bool,

    /// Export each guest invocation as an AWS X-Ray trace: its spans, its events, and the tenant
    /// it ran for. The instance role needs `xray:PutTraceSegments`.
    xray: bool,

    /// Guest metrics to CloudWatch, under the `<name>` namespace. The instance role needs
    /// `cloudwatch:PutMetricData` for it.
    metrics: bool,

    /// Background tasks through AWS: recorded in the `<name>-tasks` table, delivered on the
    /// `<name>-tasks` queue, scheduled in the `<name>-tasks` group by the `<name>-scheduler`
    /// role, all of which the deployment creates. Off leaves a testing build's tasks in memory and
    /// turns a production build's off.
    tasks: bool,

    /// Report on the clock and entropy source and exit, without mounting or
    /// running anything. For diagnosing a deployment.
    self_check: bool,

    /// The emulator's and the tests' settings; [`Testing::production`] in a production build.
    testing: Testing,
}

/// The settings only a `testing` build has: the emulator's and the tests'.
///
/// A production binary reads none of them. It takes [`Testing::production`], so each value a
/// production enclave runs with is written once, there, and no deployment can reach another.
struct Testing {
    /// Where the master secret comes from. `static` takes it from `ENCLAVE_MASTER_KEY`
    /// and stores it unsealed, for the emulator, whose NSM cannot produce a
    /// document KMS would accept.
    master_key_source: MasterKeySourceKind,

    /// 32-byte master secret, hex encoded. `static` only, and refused under
    /// `kms`: a key from configuration is a key the parent instance holds.
    master_key: Option<String>,

    /// The operator master, 64 hex characters, for the emulator: a testing
    /// build signs in through it, or with none serves unauthenticated.
    operator_master: Option<String>,

    /// Where the guest's wall-clock time comes from. The emulator has no PTP
    /// clock; `host` uses the system's.
    clock_source: ClockSource,

    /// PTP character device to read.
    ptp_device: PathBuf,

    /// Where random bytes come from. `host` is for a machine with no NSM.
    random_source: RandomSource,

    /// An S3-compatible endpoint in place of AWS's: the emulator's MinIO.
    endpoint: Option<String>,

    /// Path-style addressing, which MinIO needs.
    force_path_style: bool,

    /// Static credentials for that endpoint, under the AWS SDK's own names.
    /// Production signs as the instance's role.
    access_key_id: Option<String>,
    secret_access_key: Option<String>,
    session_token: Option<String>,

    /// Point the CloudWatch client somewhere else. An `http://` endpoint hands
    /// guest output to whatever is listening, in clear.
    guest_log_endpoint: Option<String>,

    /// Point the X-Ray client somewhere else, such as a local stand-in for the service.
    xray_endpoint: Option<String>,

    /// Point the CloudWatch metrics client somewhere else.
    metrics_endpoint: Option<String>,

    /// Point the task clients — DynamoDB, EventBridge Scheduler, SQS — at one local endpoint.
    /// An `http://` endpoint hands task metadata to whatever is listening, in clear.
    task_endpoint: Option<String>,

    /// Point the push client at a stub: an `http://` endpoint hands wake signals to
    /// whatever is listening, and requests to it are signed with a placeholder
    /// rather than the instance's role.
    push_endpoint: Option<String>,

    /// Re-sign attestation documents with a certificate chain minted at boot.
    ///
    /// Only useful under an emulator. QEMU's NSM produces documents with
    /// genuine contents — the real PCR0 of the image, the PCR16 the runtime
    /// measured — inside an envelope it does not sign: its source says *"we
    /// don't actually sign the data, so we use -1 as the 'alg' value"*, and -1
    /// is not a COSE algorithm. A client meeting one has to pass
    /// `--unsigned-emulator`, which skips the signature, the chain and the
    /// validity windows entirely.
    ///
    /// With this set, the runtime asks the device for a document and re-signs
    /// that same payload, so a client pins the reported root and runs every
    /// check it would run against hardware. It proves nothing about *who*
    /// produced a document — the key is minted inside an image its operator
    /// controls. Read by a testing build only: a production build has no way
    /// to re-sign, so nothing there asks.
    #[cfg_attr(not(any(test, feature = "testing")), allow(dead_code))]
    cosign_attestations: bool,
}

impl Testing {
    /// What a production enclave runs with.
    #[cfg_attr(any(test, feature = "testing"), allow(dead_code))]
    fn production() -> Self {
        Testing {
            master_key_source: MasterKeySourceKind::Kms,
            master_key: None,
            operator_master: None,
            clock_source: ClockSource::Ptp,
            ptp_device: PathBuf::from(DEFAULT_PTP_DEVICE),
            random_source: RandomSource::Nsm,
            endpoint: None,
            force_path_style: false,
            access_key_id: None,
            secret_access_key: None,
            session_token: None,
            guest_log_endpoint: None,
            xray_endpoint: None,
            metrics_endpoint: None,
            task_endpoint: None,
            push_endpoint: None,
            cosign_attestations: false,
        }
    }

    /// The emulator's and the tests' settings, read the way [`Settings::from_env`] reads its own.
    #[cfg(any(test, feature = "testing"))]
    fn from_env(env: &Env) -> Result<Testing> {
        read!(env, master_key_source: parsed(MasterKeySourceKind::Kms, MasterKeySourceKind::parse));
        read!(env, master_key: optional());
        read!(env, operator_master: optional());
        read!(env, clock_source: parsed(ClockSource::Ptp, ClockSource::parse));
        read!(env, ptp_device: or(DEFAULT_PTP_DEVICE));
        read!(env, random_source: parsed(RandomSource::Nsm, RandomSource::parse));
        read!(env, endpoint: optional());
        read!(env, force_path_style: flag());
        read!(env, aws access_key_id: optional());
        read!(env, aws secret_access_key: optional());
        read!(env, aws session_token: optional());
        read!(env, guest_log_endpoint: optional());
        read!(env, xray_endpoint: optional());
        read!(env, metrics_endpoint: optional());
        read!(env, task_endpoint: optional());
        read!(env, push_endpoint: optional());
        read!(env, cosign_attestations: flag());
        Ok(Testing {
            master_key_source,
            master_key,
            operator_master,
            clock_source,
            ptp_device: ptp_device.into(),
            random_source,
            endpoint,
            force_path_style,
            access_key_id,
            secret_access_key,
            session_token,
            guest_log_endpoint,
            xray_endpoint,
            metrics_endpoint,
            task_endpoint,
            push_endpoint,
            cosign_attestations,
        })
    }
}

impl Settings {
    /// Read every setting through `get`: `std::env::var` in the enclave, a map in the tests.
    fn from_env(get: &dyn Fn(&str) -> Option<String>) -> Result<Settings> {
        let env = Env(get);
        read!(env, name: required());
        anyhow::ensure!(
            valid_name(&name),
            "ENCLAVE_NAME={name:?} must be 1-50 lowercase letters, digits and hyphens, starting \
             and ending with a letter or digit: it is part of every resource name the deployment \
             uses"
        );
        read!(env, bucket_prefix: or(""));
        read!(env, id: or("00000000000000000000000000000000"));
        // A production image must say which release it is; a testing build is release 1.
        read!(env, release: number(cfg!(any(test, feature = "testing")).then_some(1)));
        read!(env, root_retention_secs: number(Some(enclave_runtime::DEFAULT_ROOT_RETENTION.as_secs())));
        anyhow::ensure!(
            root_retention_secs >= MIN_ROOT_RETENTION_SECS,
            "ENCLAVE_ROOT_RETENTION_SECS is {root_retention_secs}: under a day \
             ({MIN_ROOT_RETENTION_SECS}) it protects nothing worth the name"
        );
        read!(env, aws region: or("us-east-1"));
        read!(env, account_id: optional());
        read!(env, push_app_id: optional());
        read!(env, guest_logs: flag());
        read!(env, xray: flag());
        read!(env, metrics: flag());
        read!(env, tasks: flag());
        read!(env, self_check: flag());
        #[cfg(any(test, feature = "testing"))]
        let testing = Testing::from_env(&env)?;
        #[cfg(not(any(test, feature = "testing")))]
        let testing = Testing::production();
        Ok(Settings {
            name,
            bucket_prefix,
            id,
            release,
            root_retention_secs,
            region,
            account_id,
            push_app_id,
            guest_logs,
            xray,
            metrics,
            tasks,
            self_check,
            testing,
        })
    }

    /// The Object-Locked bucket: each pool's anchor chain, the tenant registry, each release's
    /// sealed key and caches, and the guest. COMPLIANCE retention on it is the entire rollback
    /// guarantee; the state itself is on the pools.
    fn roots_bucket(&self) -> String {
        format!("{}-roots", self.name)
    }

    /// The prefix each release's KMS key alias is under, `<prefix>/<sha256(pcr0 ‖ pcr16)>`. Read
    /// at a release's first boot only: the key's own ARN goes into the release's pointer, and
    /// every boot after uses that.
    fn kms_key_alias(&self) -> String {
        format!("alias/{}", self.name)
    }

    /// The base of the SSM parameters holding each release's KMS ciphertext,
    /// `<base>/<sha256(pcr0 ‖ pcr16)>/<the ciphertext's digest>`.
    fn master_key_parameter(&self) -> String {
        format!("/{}/master-key", self.name)
    }

    /// The SSM `SecureString` the operator writes its master to: 64 hex characters, read the
    /// first time a registration or sign-in needs it. Every wallet key's runtime half is derived
    /// from it, and its share sealed under it in the tenant's record.
    fn operator_master_parameter(&self) -> String {
        format!("/{}/operator-master", self.name)
    }

    /// Where guest output goes beyond the console, in its `guest` stream.
    fn guest_log_group(&self) -> String {
        format!("/{}/guest", self.name)
    }
}

/// A deployment name every resource name it is part of accepts. An S3 bucket's are the
/// strictest: lowercase, and `<name>-roots` at most 63 characters.
fn valid_name(name: &str) -> bool {
    (1..=50).contains(&name.len())
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        && !name.starts_with('-')
        && !name.ends_with('-')
}

impl Settings {
    /// Everything about notifications that can be decided without a network.
    ///
    /// A malformed application id fails at boot rather than the first time somebody is waiting
    /// to be woken; whether the application can deliver is the probe's to find out, once there
    /// is a network.
    fn notify_settings(&self) -> Result<Option<NotifySettings>> {
        match (
            nonempty(&self.push_app_id),
            nonempty(&self.testing.push_endpoint),
        ) {
            (None, None) => Ok(None),
            (None, Some(_)) => anyhow::bail!(
                "ENCLAVE_PUSH_ENDPOINT was given without ENCLAVE_PUSH_APP_ID, so there is no \
                 application to send through"
            ),
            (Some(app_id), endpoint) => {
                anyhow::ensure!(
                    enclave_runtime::notify::valid_app_id(&app_id),
                    "ENCLAVE_PUSH_APP_ID must be the application's id, 1-64 letters and digits"
                );
                Ok(Some(NotifySettings { app_id, endpoint }))
            }
        }
    }

    /// Where guest output goes, beyond the console: the `guest` stream of the deployment's group.
    fn guest_log_config(&self) -> Option<enclave_runtime::CloudWatchConfig> {
        self.guest_logs.then(|| enclave_runtime::CloudWatchConfig {
            log_group: self.guest_log_group(),
            log_stream: GUEST_LOG_STREAM.to_string(),
            region: self.region.clone(),
            endpoint: self.testing.guest_log_endpoint.clone(),
        })
    }

    /// Where background tasks are scheduled: all four settings, or none.
    fn background_tasks(&self) -> Result<Option<enclave_runtime::tasks::BackgroundTasks>> {
        if !self.tasks {
            #[cfg(any(test, feature = "testing"))]
            return Ok(Some(Default::default()));
            #[cfg(not(any(test, feature = "testing")))]
            return Ok(None);
        }
        let account = self
            .account_id
            .as_deref()
            .map(str::trim)
            .filter(|a| a.len() == 12 && a.bytes().all(|b| b.is_ascii_digit()))
            .context(
                "ENCLAVE_TASKS needs ENCLAVE_ACCOUNT_ID, the account's 12 digits: the task \
                 queue's URL and the scheduler role's ARN carry it",
            )?;
        let tasks = format!("{}-tasks", self.name);
        Ok(Some(enclave_runtime::tasks::BackgroundTasks {
            limits: Default::default(),
            backend: enclave_runtime::tasks::TaskBackend::Aws(
                enclave_runtime::tasks::TasksConfig {
                    table: tasks.clone(),
                    queue_url: format!(
                        "https://sqs.{}.amazonaws.com/{account}/{tasks}",
                        self.region
                    ),
                    schedule_group: tasks,
                    scheduler_role_arn: format!(
                        "arn:aws:iam::{account}:role/{}-scheduler",
                        self.name
                    ),
                    region: self.region.clone(),
                    endpoint: self.testing.task_endpoint.clone(),
                },
            ),
        }))
    }

    fn mount_config(&self) -> Result<MountConfig> {
        Ok(MountConfig {
            roots_bucket: self.roots_bucket(),
            region: self.region.clone(),
            endpoint: self.testing.endpoint.clone(),
            access_key_id: self.testing.access_key_id.clone(),
            secret_access_key: self.testing.secret_access_key.clone(),
            session_token: self.testing.session_token.clone(),
            force_path_style: self.testing.force_path_style,
            bucket_prefix: self.bucket_prefix.clone(),
            fs_id: enclave_runtime::parse_fs_id(&self.id)?,
            skip_bucket_probe: false,
            request_timeout: S3_TIMEOUT,
            root_retention: Duration::from_secs(self.root_retention_secs),
        })
    }

    fn master_key_config(&self) -> Result<enclave_runtime::MasterKeyConfig> {
        let kms = self.testing.master_key_source == MasterKeySourceKind::Kms;
        Ok(enclave_runtime::MasterKeyConfig {
            kind: self.testing.master_key_source,
            master_key: self.testing.master_key.clone(),
            // Only a KMS source looks for a key and a parameter: a testing build's static key
            // has neither to find.
            kms_key_alias: kms.then(|| self.kms_key_alias()),
            parameter: kms.then(|| self.master_key_parameter()),
            environment: KMS_ENVIRONMENT.to_string(),
            fs_id: enclave_runtime::parse_fs_id(&self.id)?,
            region: self.region.clone(),
            kms_endpoint: None,
            ssm_endpoint: None,
            // A production build always signs in through the operator master in SSM. A testing
            // build takes the emulator's fixed one, or with none serves unauthenticated.
            operator_master_parameter: (!cfg!(any(test, feature = "testing")))
                .then(|| self.operator_master_parameter()),
            operator_master: self.testing.operator_master.clone(),
            access_key_id: self.testing.access_key_id.clone(),
            secret_access_key: self.testing.secret_access_key.clone(),
            session_token: self.testing.session_token.clone(),
        })
    }
}

/// The guest file's setting naming its release: written into every anchor
/// beside the runtime's, and refused when a pool names a higher one. A guest
/// that names none is release 0, and gets no protection from an older guest.
const GUEST_RELEASE_SETTING: &str = "AEGIRA_RELEASE";

fn guest_release(env: &[(String, String)]) -> Result<u64> {
    match env.iter().find(|(n, _)| n == GUEST_RELEASE_SETTING) {
        Some((_, v)) => v
            .trim()
            .parse()
            .with_context(|| format!("{GUEST_RELEASE_SETTING}={v:?} is not a release number")),
        None => Ok(0),
    }
}

#[tokio::main]
async fn main() -> std::process::ExitCode {
    init_tracing();

    match run().await {
        Ok(outcome) => {
            if outcome.is_success() {
                tracing::info!("guest exited successfully");
            } else {
                tracing::warn!(exit_code = outcome.exit_code(), "guest exited non-zero");
            }
            exit_code(outcome.exit_code())
        }
        Err(e) => {
            tracing::error!(
                error = format!("{e:#}"),
                "runtime failed to start the guest"
            );
            exit_code(EXIT_RUNTIME_FAILURE)
        }
    }
}

async fn run() -> Result<enclave_runtime::GuestOutcome> {
    let settings = Settings::from_env(&|name| std::env::var(name).ok())?;

    let clock = open_clock(settings.testing.clock_source, &settings.testing.ptp_device)?;
    let entropy = open_entropy(
        settings.testing.random_source,
        Path::new(DEFAULT_NSM_DEVICE),
    )?;
    enclave_runtime::random::install(entropy.clone())?;

    /// Wrap the device so its documents carry a signature, if this build can.
    ///
    /// Two definitions rather than a runtime branch: a production binary has no
    /// cosigning code at all, so no deployment can talk it into signing
    /// attestations with a key it minted itself.
    #[cfg(any(test, feature = "testing"))]
    fn cosign(
        settings: &Settings,
        entropy: std::sync::Arc<dyn nitro_nsm::Nsm>,
    ) -> Result<std::sync::Arc<dyn nitro_nsm::Nsm>> {
        use base64::Engine as _;

        if !settings.testing.cosign_attestations {
            return Ok(entropy);
        }
        let cosigning = enclave_runtime::testing::CosigningNsm::wrap(entropy)?;
        // At `warn`, and printed in full. A client cannot check anything
        // without this value, and it is minted fresh at every boot — so it has
        // to leave by the one channel the parent already reads, and it has to
        // stand out from the boot log around it.
        tracing::warn!(
            trust_root = %base64::engine::general_purpose::STANDARD.encode(cosigning.trust_root()),
            "attestation documents are signed with a chain minted at boot, not by Nitro \
             hardware; a client must pin the root below, and it means only that this image \
             produced the document"
        );
        Ok(std::sync::Arc::new(cosigning))
    }

    #[cfg(not(any(test, feature = "testing")))]
    fn cosign(
        _settings: &Settings,
        entropy: std::sync::Arc<dyn nitro_nsm::Nsm>,
    ) -> Result<std::sync::Arc<dyn nitro_nsm::Nsm>> {
        Ok(entropy)
    }

    let entropy = cosign(&settings, entropy)?;

    if settings.self_check {
        clock_check(clock.as_ref())?;
        println!();
        entropy_check(entropy.as_ref())?;
        return Ok(enclave_runtime::GuestOutcome::Success);
    }

    // Before anything that needs a socket. Mounting reaches S3, so a runtime
    // that mounted first would fail with an S3 error that says nothing about
    // the real cause.
    let _network = enclave_runtime::bring_up(&NetworkConfig {
        mode: NetworkMode::Gvproxy,
        ..Default::default()
    })?;

    let keys = enclave_runtime::open_key_source(&settings.master_key_config()?, entropy.clone())?;
    let guest_source = GuestSource::Object {
        key: GUEST_OBJECT.to_string(),
    };
    tracing::info!(
        key_source = keys.describe(),
        guest = %guest_source,
        "starting"
    );

    let mount_config = settings.mount_config()?;
    let roots = enclave_runtime::connect(&mount_config).await?;

    // The guest, before anything asks for a key. KMS releases the key against
    // an attestation carrying PCR16, so PCR16 has to be final by then: measured,
    // and locked so nothing can extend it afterwards. These same bytes are what
    // get compiled and served below, so what was measured is what runs.
    let component = enclave_runtime::fetch_guest(&guest_source, &roots).await?;
    let guest_pcr = enclave_runtime::measure_guest(entropy.as_ref(), &component)?;
    tracing::info!(
        guest = %guest_source,
        guest_sha256 = %hex::encode(nitro_attestation::sha256(&component)),
        pcr16 = %hex::encode(guest_pcr),
        "guest measured into PCR16 and locked"
    );

    // The guest's environment is the settings its file carries, measured into PCR16 with its
    // code, and nothing else — see `env::from_guest`. Names only: a value can be a credential.
    let env = enclave_runtime::env::from_guest(&component)?;
    let release = enclave_runtime::Release {
        runtime: settings.release,
        guest: guest_release(&env)?,
    };

    // This release's key, and the tenants it kept. Every other tenant's pool
    // waits for its owner's key.
    let booted = enclave_runtime::boot(
        &roots,
        &mount_config,
        &enclave_runtime::BootConfig {
            disk: enclave_runtime::Disk::Parent,
            release,
        },
        &entropy,
        &keys,
        &clock,
    )
    .await?;

    tracing::info!(
        mode = ?booted.mode,
        version = %hex::encode(booted.vid),
        pcr0 = %hex::encode(booted.pair.pcr0),
        pcr16 = %hex::encode(booted.pair.pcr16),
        %release,
        resumed = booted.resumed,
        "version established"
    );

    let zfs = booted.zfs.clone();

    tracing::info!(
        names = %env.iter().map(|(n, _)| n.as_str()).collect::<Vec<_>>().join(", "),
        "guest environment: the settings the guest file carries"
    );

    /// Open the emulator's host to guests, but not the runtime's own services on it.
    ///
    /// The host is where an emulator's services live — an ASP, a payout platform — and where
    /// the runtime's own are too: its store, its push stub. A guest may reach the first
    /// and never the second, so the second are named by the runtime's own settings, which cannot
    /// drift from where those services are. Two definitions, as above: a production binary has
    /// no host to open.
    #[cfg(any(test, feature = "testing"))]
    fn open_dev_host(settings: &Settings) -> anyhow::Result<()> {
        let mut own = Vec::new();
        for url in [
            &settings.testing.endpoint,
            &settings.testing.guest_log_endpoint,
            &settings.testing.push_endpoint,
        ]
        .into_iter()
        .flatten()
        {
            let uri: http::Uri = url.parse().with_context(|| format!("{url} is not a URL"))?;
            own.push(uri.port_u16().unwrap_or(match uri.scheme_str() {
                Some("https") => 443,
                _ => 80,
            }));
        }
        own.sort_unstable();
        own.dedup();
        tracing::warn!(
            ?own,
            "guests may reach the public internet, and the emulator's host on every port but these"
        );
        enclave_runtime::serve::egress::admit_dev_host(own);
        Ok(())
    }

    #[cfg(not(any(test, feature = "testing")))]
    fn open_dev_host(_settings: &Settings) -> anyhow::Result<()> {
        tracing::info!("guests may reach the public internet, and nothing else");
        Ok(())
    }

    // The certificate every connection is served: made here, at every boot,
    // with a key that exists only in this enclave's memory. Clients trust it
    // because an attestation binds its hash, not because a CA signed it —
    // see `serve::tls`.
    let certificate = std::sync::Arc::new(enclave_runtime::TlsIdentity::self_signed(&[])?);
    tracing::info!(listen = %HTTP_LISTEN, "serving guest");

    // Not a choice. An enclave nobody can verify is an enclave for nothing, and
    // a flag that turns verification off is a flag that can be turned off by
    // whoever starts the process — which inside an enclave is the party the
    // enclave exists to exclude.
    let attestation = Some(entropy.clone());

    // Per-client views of the one pool. Each client's guest sees its
    // own dataset as `/`, through a fresh instance per request, so a
    // client costs a dataset and a lock.
    //
    // A client is serialised against itself and nobody else, so two
    // clients can execute guest code at the same time. A guest is
    // written for that; it is not a deployment decision.
    let tenancy = Some(std::sync::Arc::new(enclave_runtime::Tenancy::new(
        enclave_runtime::PoolLimits::default(),
    )));

    // Where guests may send is no setting: the public internet, checked on every connect — see
    // `serve::egress`. Only the emulator widens it, to its host.
    open_dev_host(&settings)?;

    // Signed approvals, when the deployment has an operator master: a tenant's
    // wallet key is made with it, and sign-in is a signature with that key.
    let authentication =
        match enclave_runtime::open_operator_master(&settings.master_key_config()?)? {
            Some(master) => {
                let keys = std::sync::Arc::new(enclave_runtime::signer::Keys::new(
                    zfs.registry().clone(),
                    std::sync::Arc::new(master),
                ));
                let gate = std::sync::Arc::new(enclave_runtime::Gate::new(
                    enclave_runtime::TokenStore::new(
                        enclave_runtime::auth::DEFAULT_TOKEN_TTL,
                        enclave_runtime::DEFAULT_TOKEN_CAPACITY,
                    ),
                ));
                let auth = std::sync::Arc::new(enclave_runtime::AuthEndpoints::new(
                    gate.clone(),
                    keys,
                    zfs.clone(),
                    entropy.clone(),
                    enclave_runtime::auth::ChallengeStore::new(
                        enclave_runtime::auth::DEFAULT_TTL,
                        enclave_runtime::auth::DEFAULT_CAPACITY,
                    ),
                ));
                tracing::info!(
                    "registration is open to anyone; requiring an approval signed with the \
                 tenant's wallet share per request"
                );
                Some((auth, gate))
            }
            None => None,
        };

    // The console always, and CloudWatch alongside it when configured.
    // Additive on purpose: the console is often the only thing working
    // while a deployment is being brought up, and the destination that
    // needs the network is exactly the part that may not be.
    //
    // TracingLogSink first, so console output is never queued behind
    // the network sink.
    let mut sinks: Vec<std::sync::Arc<dyn enclave_runtime::GuestLogSink>> =
        vec![std::sync::Arc::new(enclave_runtime::TracingLogSink)];
    let mut log_forwarder = None;

    // Which image is running, for the guest log stream and on every trace. A fixed stream name is
    // shared by every boot and every image, so without this nothing in it says which enclave
    // produced which line.
    let image = attestation
        .as_ref()
        .and_then(|nsm| match nsm.describe_pcr(0) {
            Ok(pcr) => Some(hex::encode(pcr.value)),
            Err(e) => {
                tracing::warn!(error = %e, "could not read PCR0 for guest logs and traces");
                None
            }
        });

    if let Some(config) = settings.guest_log_config() {
        // Bounded, like everything else on this path. Building the
        // client resolves a credential provider, and that reaches IMDS
        // through gvproxy — a path this deployment has not verified. A
        // logging client must never be what decides whether the enclave
        // binds its listener.
        let destination: Option<std::sync::Arc<dyn enclave_runtime::LogDestination>> =
            match tokio::time::timeout(
                enclave_runtime::STARTUP_PROBE_TIMEOUT,
                enclave_runtime::CloudWatchDestination::connect(&config),
            )
            .await
            {
                Ok(destination) => Some(std::sync::Arc::new(destination)),
                Err(_) => {
                    tracing::error!(
                        timeout = ?enclave_runtime::STARTUP_PROBE_TIMEOUT,
                        log_group = %config.log_group,
                        "could not build a CloudWatch client in time; guest output \
                         stays on the console only. Check that the enclave can reach \
                         IMDS through gvproxy."
                    );
                    None
                }
            };

        // The boot marker is the probe. A definitive refusal — the
        // stream is not there, or this identity may not write to it —
        // stops the boot: it is a deployment mistake, and discovering
        // it only from a console line that was meant to be shipped off
        // the box would mean running blind indefinitely. Anything
        // transient does not stop the boot, because CloudWatch having a
        // bad day must not be a cosigner outage.
        if let Some(destination) = destination {
            // Carried to the forwarder when the probe did not manage to
            // write it, so a stream that recovers still ends up saying
            // which image is writing to it. `None` once it is written.
            let mut marker = None;
            match enclave_runtime::open_guest_log_stream(
                &destination,
                image.as_deref(),
                &config.region,
            )
            .await
            {
                Ok(()) => tracing::info!(
                    log_group = %config.log_group,
                    log_stream = %config.log_stream,
                    image = image.as_deref().unwrap_or("(unknown)"),
                    "guest output is going to CloudWatch"
                ),
                Err(enclave_runtime::PutError::Definitive(e)) => anyhow::bail!(
                    "guest logging is configured for {}/{} but that destination refused \
                 us: {e}. The log group and stream must exist and this enclave's \
                 credentials must carry logs:PutLogEvents for them. Leave \
                 ENCLAVE_GUEST_LOGS off for console-only logging.",
                    config.log_group,
                    config.log_stream,
                ),
                Err(enclave_runtime::PutError::Transient(e)) => {
                    tracing::warn!(
                        error = %e,
                        log_group = %config.log_group,
                        "could not reach CloudWatch at startup; guest logs will retry"
                    );
                    marker = Some(enclave_runtime::guest_log_boot_marker(
                        image.as_deref(),
                        &config.region,
                    ));
                }
            }

            let (sink, forwarder) = enclave_runtime::start_guest_log_forwarder(destination, marker);
            sinks.push(std::sync::Arc::new(sink));
            log_forwarder = Some(forwarder);
        }
    }

    // Guest spans and metrics. Bounded like the log client, for the same reason: each client
    // resolves a credential provider through gvproxy, and telemetry that cannot be set up must
    // leave the guest's calls working and the listener binding.
    let telemetry = start_telemetry(&settings, image.clone()).await?;

    // Decided before the listener binds, so a setting that cannot work is a boot failure rather
    // than a surprise on the first wake. Whether the application can deliver is the probe's to
    // find out once serving starts.
    let notify = match settings.notify_settings()? {
        None => None,
        Some(push) => {
            tracing::info!(
                app = %push.app_id,
                "notifications are enabled; wake signals carry no content"
            );
            let credentials = match &push.endpoint {
                // The emulator's stub checks no signature, and the static keys in an emulator's
                // image are its object store's: neither is the instance's role.
                Some(_) => aws_credential_types::provider::SharedCredentialsProvider::new(
                    aws_credential_types::Credentials::new(
                        "push-stub",
                        "push-stub",
                        None,
                        None,
                        "push-stub",
                    ),
                ),
                None => enclave_runtime::notify::instance_role(),
            };
            Some(enclave_runtime::NotifyConfig {
                app_id: push.app_id,
                region: settings.region.clone(),
                endpoint: push.endpoint,
                credentials,
            })
        }
    };

    // Before the listener binds, so no request can produce guest output
    // before there is a task consuming it. Held for the server's
    // lifetime and drained explicitly below.
    let (guest_logs, log_collector) = enclave_runtime::telemetry::logs::start(std::sync::Arc::new(
        enclave_runtime::FanOutSink::new(sinks),
    ));

    let guest = GuestEnvironment::new(zfs, clock, entropy, &env, &[], guest_logs)?;
    let served = serve_component(
        &component,
        guest,
        ServeConfig {
            notify,
            telemetry,
            // Whether tasks run is the guest's to say, by exporting `run-task`.
            background_tasks: settings.background_tasks()?,
            addr: HTTP_LISTEN,
            certificate: Some(certificate),
            attestation,
            tenancy,
            authentication,
            ..ServeConfig::default()
        },
    )
    .await;
    // Drained whether the accept loop stopped cleanly or failed, and
    // on a bounded deadline — a log that will not flush must not be
    // what keeps an enclave from stopping.
    log_collector.shutdown().await;
    // After the collector, so records it was still holding reach the
    // forwarder before the forwarder is asked to flush. Both deadlines
    // are bounded; neither can hold the enclave open.
    if let Some(forwarder) = log_forwarder {
        forwarder.shutdown().await;
    }
    served?;
    // `serve_component` only returns on error; reaching here means the
    // accept loop stopped, which is not a guest exit.
    Ok(enclave_runtime::GuestOutcome::Failed)
}

/// Print what the configured clock actually reports.
///
/// The delta against `CLOCK_REALTIME` is the interesting column: a PTP clock
/// disciplined by an external source and a host clock set by the hypervisor
/// have no reason to agree, and how far apart they are is exactly what this
/// feature exists to expose.
fn clock_check(clock: &dyn enclave_runtime::TrustedClock) -> Result<()> {
    use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

    println!("clock source: {}", clock.describe());
    println!("resolution:   {:?}", clock.resolution());
    println!();
    println!(
        "  {:<26} {:>16} {:>12}",
        "reading", "vs CLOCK_REALTIME", "read time"
    );

    let mut previous: Option<Duration> = None;
    for _ in 0..5 {
        let started = Instant::now();
        let now = clock.now()?;
        let read_time = started.elapsed();
        let realtime = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("host clock before the epoch");

        // Signed skew, in milliseconds.
        let skew_ms = now.as_secs_f64() * 1e3 - realtime.as_secs_f64() * 1e3;

        if let Some(prev) = previous {
            if now < prev {
                anyhow::bail!("clock went backwards: {:?} then {:?}", prev, now);
            }
        }
        previous = Some(now);

        println!(
            "  {:<26} {:>13.3} ms {:>9.1} us",
            format!("{}.{:09}", now.as_secs(), now.subsec_nanos()),
            skew_ms,
            read_time.as_secs_f64() * 1e6
        );
        std::thread::sleep(Duration::from_millis(20));
    }

    println!();
    println!("clock advanced monotonically across 5 readings");
    Ok(())
}

fn exit_code(code: i32) -> std::process::ExitCode {
    // `ExitCode` is a byte; a guest exit code outside that range would wrap
    // silently, so clamp it to something a parent can read unambiguously.
    std::process::ExitCode::from(u8::try_from(code).unwrap_or(1))
}

fn init_tracing() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        // Targets are shown, and that is not cosmetic. The console carries the
        // runtime's own events *and* whatever a guest chose to write, and the
        // target is the one thing separating them that a guest cannot
        // influence — see `enclave_runtime::telemetry::logs`. Guest lines say
        // `guest`; everything else names a module in this runtime. Hiding it
        // was right when every line was the runtime's own; it stopped being
        // right when untrusted text started sharing the same console.
        //
        // `RUST_LOG=guest=warn` filters guest output independently either way,
        // but an operator reading the console should not have to know that to
        // tell which lines are trustworthy.
        .with_target(true)
        .compact()
        .init();
}

/// Report on the entropy source, and apply the crude checks that catch a
/// device returning constants.
///
/// These prove nothing about randomness quality — no cheap test can — but they
/// do catch the failure modes that actually occur: a stub that returns zeros, a
/// buffer never written, a device answering the same block every time. That is
/// exactly how an emulator or a misconfigured driver misbehaves.
fn entropy_check(source: &dyn enclave_runtime::Nsm) -> Result<()> {
    use std::time::Instant;

    println!("entropy source: {}", source.describe());

    let mut first = [0u8; 64];
    let started = Instant::now();
    source.get_random(&mut first)?;
    let first_read = started.elapsed();

    let mut second = [0u8; 64];
    source.get_random(&mut second)?;

    if first.iter().all(|&b| b == 0) {
        anyhow::bail!("entropy source returned all zeros");
    }
    if first.iter().all(|&b| b == first[0]) {
        anyhow::bail!("entropy source returned a constant byte {:#04x}", first[0]);
    }
    if first == second {
        anyhow::bail!("two draws returned identical bytes; the source is not advancing");
    }

    // A byte histogram over a larger sample. Not a randomness test — with 4096
    // samples over 256 buckets the mean is 16, and anything above ~80 in one
    // bucket is a stuck source rather than bad luck.
    let mut bulk = vec![0u8; 4096];
    let bulk_started = Instant::now();
    source.get_random(&mut bulk)?;
    let bulk_read = bulk_started.elapsed();

    let mut histogram = [0u32; 256];
    for &b in &bulk {
        histogram[b as usize] += 1;
    }
    let peak = histogram.iter().copied().max().unwrap_or(0);
    let empty = histogram.iter().filter(|&&c| c == 0).count();
    if peak > 80 {
        anyhow::bail!("byte histogram peaks at {peak} of 4096; the source looks stuck");
    }

    println!(
        "  sample:      {}",
        first[..16]
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<Vec<_>>()
            .join("")
    );
    println!("  histogram:   peak {peak}, {empty} of 256 values unseen (mean 16)");
    println!(
        "  read cost:   {:.1} us for 64 bytes, {:.1} us for 4096",
        first_read.as_secs_f64() * 1e6,
        bulk_read.as_secs_f64() * 1e6
    );
    println!();
    println!("entropy source produced varying, non-constant bytes");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::{BTreeMap, BTreeSet};

    /// Settings from these variables, beside the one every boot needs.
    fn try_settings(vars: &[(&str, &str)]) -> Result<Settings> {
        let mut env = BTreeMap::from([("ENCLAVE_NAME".to_string(), "test".to_string())]);
        env.extend(vars.iter().map(|(k, v)| (k.to_string(), v.to_string())));
        Settings::from_env(&|name| env.get(name).cloned())
    }

    fn settings_from(vars: &[(&str, &str)]) -> Settings {
        try_settings(vars).expect("valid settings")
    }

    /// The names come from the fields, so they cannot drift from the code; this keeps them from
    /// drifting from the image. A variable the image sets that nothing reads would leave its
    /// setting at its default, without a word.
    #[test]
    fn every_variable_the_image_sets_is_read() {
        let asked = std::cell::RefCell::new(BTreeSet::new());
        Settings::from_env(&|name| {
            asked.borrow_mut().insert(name.to_string());
            (name == "ENCLAVE_NAME").then(|| "test".to_string())
        })
        .expect("valid settings");
        let image: BTreeSet<&str> = include_str!("../../flake.nix")
            .lines()
            .filter_map(|line| line.trim().split_once(" = "))
            .map(|(name, _)| name)
            .filter(|name| name.starts_with("ENCLAVE_"))
            .collect();
        assert!(
            image.contains("ENCLAVE_NAME") && image.contains("ENCLAVE_MASTER_KEY_SOURCE"),
            "the image's variables were not found: {image:?}"
        );
        let asked = asked.into_inner();
        let unread: Vec<_> = image
            .iter()
            .filter(|name| !asked.contains(**name))
            .collect();
        assert!(
            unread.is_empty(),
            "the image sets {unread:?}, which nothing reads"
        );
    }

    #[test]
    fn the_name_is_required_and_fits_every_resource_it_names() {
        assert!(Settings::from_env(&|_| None).is_err());
        for bad in [
            "",
            "Upper",
            "under_score",
            "-lead",
            "trail-",
            &"x".repeat(51),
        ] {
            assert!(try_settings(&[("ENCLAVE_NAME", bad)]).is_err(), "{bad:?}");
        }
        assert!(try_settings(&[("ENCLAVE_NAME", "mm-vault-mutinynet")]).is_ok());
    }

    /// One name, and every resource named after it by one rule — the names a
    /// deployment already uses.
    #[test]
    fn the_deployment_s_resources_are_named_after_it() {
        let settings = settings_from(&[
            ("ENCLAVE_NAME", "mm-vault-mutinynet"),
            ("AWS_REGION", "eu-west-2"),
            ("ENCLAVE_ACCOUNT_ID", "123456789012"),
            ("ENCLAVE_TASKS", "1"),
            ("ENCLAVE_METRICS", "1"),
        ]);
        assert_eq!(settings.roots_bucket(), "mm-vault-mutinynet-roots");
        assert_eq!(settings.kms_key_alias(), "alias/mm-vault-mutinynet");
        assert_eq!(
            settings.master_key_parameter(),
            "/mm-vault-mutinynet/master-key"
        );
        assert_eq!(
            settings.operator_master_parameter(),
            "/mm-vault-mutinynet/operator-master"
        );
        assert_eq!(settings.guest_log_group(), "/mm-vault-mutinynet/guest");
        let tasks = settings.background_tasks().unwrap().expect("tasks on");
        let enclave_runtime::tasks::TaskBackend::Aws(tasks) = tasks.backend else {
            panic!("tasks through AWS");
        };
        assert_eq!(tasks.table, "mm-vault-mutinynet-tasks");
        assert_eq!(tasks.schedule_group, "mm-vault-mutinynet-tasks");
        assert_eq!(
            tasks.queue_url,
            "https://sqs.eu-west-2.amazonaws.com/123456789012/mm-vault-mutinynet-tasks"
        );
        assert_eq!(
            tasks.scheduler_role_arn,
            "arn:aws:iam::123456789012:role/mm-vault-mutinynet-scheduler"
        );
    }

    #[test]
    fn tasks_through_aws_need_the_account() {
        let Err(err) = settings_from(&[("ENCLAVE_TASKS", "1")]).background_tasks() else {
            panic!("tasks through AWS without an account were accepted");
        };
        assert!(format!("{err:#}").contains("ENCLAVE_ACCOUNT_ID"), "{err:#}");
    }

    /// What a production enclave runs with: every value written once, in
    /// `Testing::production`, and nothing a deployment could change.
    #[test]
    fn a_production_build_takes_its_key_from_kms_and_its_time_from_ptp() {
        let production = Testing::production();
        assert_eq!(production.master_key_source, MasterKeySourceKind::Kms);
        assert!(production.master_key.is_none());
        assert_eq!(production.clock_source, ClockSource::Ptp);
        assert_eq!(production.random_source, RandomSource::Nsm);
        assert!(production.endpoint.is_none() && production.access_key_id.is_none());
        assert!(production.push_endpoint.is_none() && production.guest_log_endpoint.is_none());
        assert!(production.task_endpoint.is_none());
        assert!(!production.cosign_attestations);

        // And a testing build's defaults are the same, so an emulator departs
        // from production only where its image says so.
        let defaults = settings_from(&[]).testing;
        assert_eq!(defaults.master_key_source, production.master_key_source);
        assert_eq!(defaults.clock_source, production.clock_source);
        assert_eq!(defaults.random_source, production.random_source);
    }

    /// A week unless the image says otherwise, what it says reaches the mount,
    /// and under a day is refused.
    #[test]
    fn root_retention_is_a_week_unless_the_image_says_otherwise() {
        assert_eq!(
            enclave_runtime::DEFAULT_ROOT_RETENTION,
            Duration::from_secs(604_800)
        );
        assert_eq!(
            settings_from(&[])
                .mount_config()
                .expect("valid")
                .root_retention,
            enclave_runtime::DEFAULT_ROOT_RETENTION
        );
        assert_eq!(
            settings_from(&[("ENCLAVE_ROOT_RETENTION_SECS", "86400")])
                .mount_config()
                .expect("valid")
                .root_retention,
            Duration::from_secs(86_400)
        );
        assert!(try_settings(&[("ENCLAVE_ROOT_RETENTION_SECS", "3600")]).is_err());
        assert!(try_settings(&[("ENCLAVE_ROOT_RETENTION_SECS", "a day")]).is_err());
    }

    /// A boolean reads the way a person writing an environment file would expect.
    #[test]
    fn booleans_read_as_an_image_writes_them() {
        assert!(!settings_from(&[]).self_check);
        assert!(settings_from(&[("ENCLAVE_SELF_CHECK", "1")]).self_check);
        assert!(settings_from(&[("ENCLAVE_XRAY", "true")]).xray);
        assert!(!settings_from(&[("ENCLAVE_XRAY", "")]).xray);
        assert!(try_settings(&[("ENCLAVE_XRAY", "maybe")]).is_err());
    }

    /// Console-only is the default, and takes no client and no credentials.
    #[test]
    fn notifications_are_off_unless_configured() {
        assert!(settings_from(&[])
            .notify_settings()
            .expect("valid")
            .is_none());
    }

    /// An image carries the setting; a deployment blanks it. Empty is off, not
    /// malformed — the same rule the guest log settings follow.
    #[test]
    fn an_empty_setting_turns_notifications_off() {
        let settings = settings_from(&[("ENCLAVE_PUSH_APP_ID", "")]);
        assert!(settings.notify_settings().expect("valid").is_none());
    }

    /// An application id is all production names: no credential, no endpoint.
    #[test]
    fn an_application_id_is_all_a_deployment_sets() {
        let settings =
            settings_from(&[("ENCLAVE_PUSH_APP_ID", "0123456789abcdef0123456789abcdef")]);
        let notify = settings
            .notify_settings()
            .expect("valid")
            .expect("configured");
        assert_eq!(notify.app_id, "0123456789abcdef0123456789abcdef");
        assert!(notify.endpoint.is_none());
    }

    /// It goes into a URL path, so a malformed one fails at boot.
    #[test]
    fn a_malformed_application_id_is_refused() {
        assert!(settings_from(&[("ENCLAVE_PUSH_APP_ID", "../channels")])
            .notify_settings()
            .is_err());
    }

    #[test]
    fn a_stub_without_an_application_is_refused() {
        assert!(
            settings_from(&[("ENCLAVE_PUSH_ENDPOINT", "http://127.0.0.1:9180")])
                .notify_settings()
                .is_err()
        );
    }

    #[test]
    fn guest_logging_is_console_only_unless_configured() {
        assert!(settings_from(&[]).guest_log_config().is_none());
    }

    /// An empty setting means off, not malformed: the image environment is layered, and "" is
    /// how a layer says "not this one".
    #[test]
    fn an_empty_setting_turns_guest_logging_off() {
        assert!(settings_from(&[("ENCLAVE_GUEST_LOGS", "")])
            .guest_log_config()
            .is_none());
    }

    #[test]
    fn guest_output_goes_to_the_deployment_s_group() {
        let settings = settings_from(&[
            ("AWS_REGION", "eu-west-2"),
            ("ENCLAVE_GUEST_LOGS", "1"),
            ("ENCLAVE_GUEST_LOG_ENDPOINT", "http://127.0.0.1:4566"),
        ]);
        let config = settings.guest_log_config().expect("configured");
        assert_eq!(config.log_group, "/test/guest");
        assert_eq!(config.log_stream, "guest");
        assert_eq!(config.region, "eu-west-2");
        assert_eq!(config.endpoint.as_deref(), Some("http://127.0.0.1:4566"));
    }

    fn source_error(vars: &[(&str, &str)]) -> String {
        let config = settings_from(vars).master_key_config().expect("config");
        let nsm = std::sync::Arc::new(nitro_nsm::fake::FakeNsm::new());
        format!(
            "{:#}",
            enclave_runtime::open_key_source(&config, nsm)
                .expect_err("this combination must be refused")
        )
    }

    /// The refusal that matters most. An image that still carried
    /// `ENCLAVE_MASTER_KEY` would work perfectly — quietly taking its key from
    /// the parent instance, which is the whole thing KMS release prevents.
    #[test]
    fn a_plaintext_key_is_refused_under_kms() {
        let err = source_error(&[("ENCLAVE_MASTER_KEY", &"ab".repeat(32))]);
        assert!(err.contains("refused"), "unexpected error: {err}");
    }

    /// KMS finds its key and its parameter by the deployment's name; a static key has neither
    /// to find, so the two can never be configured together.
    #[test]
    fn only_kms_looks_for_a_key_by_name() {
        let kms = settings_from(&[]).master_key_config().expect("config");
        assert_eq!(kms.kms_key_alias.as_deref(), Some("alias/test"));
        assert_eq!(kms.parameter.as_deref(), Some("/test/master-key"));
        let fixed = settings_from(&[
            ("ENCLAVE_MASTER_KEY_SOURCE", "static"),
            ("ENCLAVE_MASTER_KEY", &"ab".repeat(32)),
        ])
        .master_key_config()
        .expect("config");
        assert!(fixed.kms_key_alias.is_none() && fixed.parameter.is_none());
    }

    #[test]
    fn a_static_source_names_the_key_it_is_missing() {
        assert!(
            source_error(&[("ENCLAVE_MASTER_KEY_SOURCE", "static")]).contains("ENCLAVE_MASTER_KEY")
        );
    }

    /// The encryption context is built from the filesystem id and the
    /// environment, so it is the same at mint and at open by construction —
    /// and the environment is the one every deployment always had, so keys
    /// sealed before it was a constant still open.
    #[test]
    fn the_key_config_carries_the_encryption_context_inputs() {
        let config = settings_from(&[("ENCLAVE_ID", &"cd".repeat(16))])
            .master_key_config()
            .expect("config");
        assert_eq!(config.environment, "production");
        assert_eq!(config.fs_id, [0xcd; 16]);
    }

    /// A testing build defaults to release 1; what the image says reaches
    /// the boot; and a guest names its own in its settings.
    #[test]
    fn releases_come_from_the_image_and_the_guest_file() {
        assert_eq!(settings_from(&[]).release, 1);
        assert_eq!(settings_from(&[("ENCLAVE_RELEASE", "7")]).release, 7);
        assert!(try_settings(&[("ENCLAVE_RELEASE", "seven")]).is_err());
        assert_eq!(guest_release(&[]).unwrap(), 0);
        let named = vec![("AEGIRA_RELEASE".to_string(), " 12 ".to_string())];
        assert_eq!(guest_release(&named).unwrap(), 12);
        let garbage = vec![("AEGIRA_RELEASE".to_string(), "twelve".to_string())];
        assert!(guest_release(&garbage).is_err());
    }

    #[test]
    fn an_invalid_filesystem_id_is_rejected_before_anything_is_opened() {
        assert!(settings_from(&[("ENCLAVE_ID", "not-hex")])
            .mount_config()
            .is_err());
    }

    #[test]
    fn mount_config_carries_the_settings_through() {
        let settings = settings_from(&[
            ("ENCLAVE_BUCKET_PREFIX", "tenant"),
            ("ENCLAVE_FORCE_PATH_STYLE", "1"),
        ]);
        let cfg = settings.mount_config().unwrap();
        assert_eq!(cfg.roots_bucket, "test-roots");
        assert_eq!(cfg.bucket_prefix, "tenant");
        assert!(cfg.force_path_style);
        assert_eq!(cfg.request_timeout, S3_TIMEOUT);
    }

    /// `ExitCode` is a byte. A guest exit code outside that range must not
    /// wrap into something a parent would read as success.
    #[test]
    fn out_of_range_exit_codes_do_not_wrap_to_success() {
        assert_eq!(
            format!("{:?}", exit_code(256)),
            format!("{:?}", exit_code(1))
        );
        assert_eq!(
            format!("{:?}", exit_code(-1)),
            format!("{:?}", exit_code(1))
        );
        assert_ne!(
            format!("{:?}", exit_code(256)),
            format!("{:?}", exit_code(0))
        );
    }
}
