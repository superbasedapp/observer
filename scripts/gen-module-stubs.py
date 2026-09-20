#!/usr/bin/env python3
"""Generate the module contract stubs: deploy/modules/CONTRACT.md and, per
root module (cloud x shape x layer), variables.tf / versions.tf / backend.tf,
from ONE variable table (Phase 2 plan contract C1; Phase 3 P3-D2 added the
clouds dimension). Re-run after editing the table; never hand-edit the
generated files (their header says so).

    python3 scripts/gen-module-stubs.py          # regenerate in place
    python3 scripts/gen-module-stubs.py --check  # CI: exit 1 when the tree drifts

Every row carries `clouds` (None = both clouds, or a list) and optional
per-cloud overrides of type / default / description / validation, so a name
that exists on both clouds with different prose (`location`) or a different
type (`data_state`) renders correctly per cloud from one table."""
import difflib, os, sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
ROOT = os.path.join(REPO, "deploy", "modules")
CLOUDS = ["azure", "aws"]
SHAPES = ["compact", "appliance"]
LAYERS = ["bootstrap", "data", "app"]

NOT_CHANGEME = lambda v: (f'!startswith(lower(var.{v}), "changeme")', f'{v} is still the CHANGEME placeholder; edit terraform/*.tfvars')


def var(name, typ, default, layers, shapes, description, validation, clouds=None, twin=None, **overrides):
    """One variable row. default None = required. shapes None = both. clouds None =
    both clouds. validation = (condition, message) or None. twin = the other
    cloud's name for a cloud-only row (documentation only). Keyword overrides are
    per cloud: aws={"description": ..., "default": ..., "validation": ..., "type": ...}."""
    for cloud, o in overrides.items():
        assert cloud in CLOUDS, (name, cloud)
        assert set(o) <= {"type", "default", "description", "validation"}, (name, cloud, o)
        assert clouds is None or cloud in clouds, (name, cloud)
    return dict(name=name, type=typ, default=default, layers=layers, shapes=shapes,
                description=description, validation=validation, clouds=clouds, twin=twin,
                overrides=overrides)


# Row order is the order of every rendered table and variables.tf. AWS-only rows
# sit beside their Azure twins; a cloud never sees the other cloud's rows.
V = [
 # ---- identity (all layers) ----
 var("name_prefix", "string", None, LAYERS, None,
  "3-12 lowercase alphanumerics prefixed to every resource name (also the state storage account name, so it must be globally unique-ish).",
  ('can(regex("^[a-z0-9]{3,12}$", var.name_prefix)) && var.name_prefix != "changeme"', "name_prefix must match ^[a-z0-9]{3,12}$ and not be the CHANGEME placeholder"),
  aws={"description": "3-12 lowercase alphanumerics prefixed to every resource name (also the <name_prefix>-tfstate and <name_prefix>-sor S3 bucket names, so it must be globally unique-ish)."}),
 var("location", "string", None, LAYERS, None,
  "Azure region (e.g. eastus2). Every appliance layout needs a region with availability zones (D24: app node i, the PostgreSQL instances and the NATS quorum are pinned to zones (i % 3) + 1 / 1-2 / 3 on single too, so a grow never re-zones a pet); RA-3 uses all three.", NOT_CHANGEME("location"),
  aws={"description": "AWS region (e.g. us-east-1). The roots require >= 3 availability zones (P3-D9: the region's first three from data.aws_availability_zones; D24's rule applies by index - app node i, the PostgreSQL instances and the NATS quorum are pinned to AZ index i % 3 / 0-1 / 2 on single too, so a grow never re-zones a pet); RA-3 uses all three."}),
 var("answer_set_id", "string", None, LAYERS, None,
  "The catalog answer set this deployment was rendered from (RA-1a, RA-2, ...). Informational: tagged on every resource, never used to derive a size.", None),
 var("tags", "map(string)", "{}", LAYERS, None, "Extra tags merged onto every resource.", None),
 # ---- bootstrap ----
 var("state_container_name", "string", '"tfstate"', ["bootstrap"], None, "Blob container (in the bootstrap-made storage account) that holds the data and app layer states.", None,
  clouds=["azure"]),
 # ---- data (+ app reads some of these too) ----
 var("admin_object_id", "string", None, ["data"], None,
  "Entra object id (user or group) granted Key Vault Secrets Officer, so an operator can read/rotate secrets. Never a service principal SuperBased holds.",
  ('can(regex("^[0-9a-fA-F-]{36}$", var.admin_object_id))', "admin_object_id must be a GUID"),
  clouds=["azure"], twin="admin_principal_arn"),
 var("admin_principal_arn", "string", None, ["data"], None,
  "IAM principal ARN (user or role) granted write on the deployment's Secrets Manager prefix observer-org/<name_prefix>/, so an operator can read/rotate secrets (P3-D3). Never a principal SuperBased holds.",
  ('startswith(var.admin_principal_arn, "arn:aws:iam::")', "admin_principal_arn must be an IAM principal ARN (arn:aws:iam::...)"),
  clouds=["aws"], twin="admin_object_id"),
 var("operator_cidr", "list(string)", "[]", ["data"], None,
  "Public CIDRs of the machines that run tofu apply (the app layer uploads the bundle blobs from there); added to the SoR storage account firewall beside the VNet subnets. [] = only the VNet can reach the account, and the bundle upload must run from inside it.", None,
  aws={"description": "Public CIDRs of the machines that run tofu apply (the app layer uploads the bundle objects from there); admitted by the SoR bucket policy beside the VPC's S3 gateway endpoint. [] = only the VPC can reach the bucket, and the bundle upload must run from inside it."}),
 var("ssh_public_key", "string", '""', ["data"], None,
  "OpenSSH public key for the VMs' admin user; empty = the data layer generates an ed25519 keypair and stores the PRIVATE key in Key Vault as vm-ssh-key (the public key is a data-layer output the app layer reads).", None,
  aws={"description": "OpenSSH public key for the instances' admin user; empty = the data layer generates an ed25519 keypair and stores the PRIVATE key in Secrets Manager as vm-ssh-key (the public key is a data-layer output the app layer reads). SSM Session Manager is the documented operator path (P3-D10); the key is for plain SSH from admin_cidr."}),
 var("object_store", "string", None, ["data", "app"], None, "Catalog axis object_store: local-disk (compact only) | cloud-bucket.",
  ('contains(["local-disk", "cloud-bucket"], var.object_store)', "object_store must be local-disk or cloud-bucket")),
 var("storage_replication", "string", '"LRS"', ["data"], None, "Storage account replication for the SoR account: LRS (single-zone sets) | ZRS (HA sets).",
  ('contains(["LRS", "ZRS"], var.storage_replication)', "storage_replication must be LRS or ZRS"),
  clouds=["azure"]),
 var("app_nodes", "number", None, ["data", "app"], None, "Number of --role all app VMs (Sizing app_nodes): 1 (single) or 2 (ha). One data disk is created per app node.",
  ("var.app_nodes >= 1 && var.app_nodes <= 2", "app_nodes must be 1 or 2 in Phase 2"),
  aws={"description": "Number of --role all app instances (Sizing app_nodes): 1 (single) or 2 (ha). One EBS data volume is created per app node."}),
 var("app_disk_gb", "number", None, ["data"], None, "Per app node premium data disk size in GiB (Sizing app_disk_gb): holds /var/lib/observer-org, the docker volumes and, on compact, the PostgreSQL data.", None,
  aws={"description": "Per app node EBS data volume size in GiB (Sizing app_disk_gb): holds /var/lib/observer-org, the docker volumes and, on compact, the PostgreSQL data."}),
 var("app_disk_sku", "string", '"Premium_LRS"', ["data"], None, "Managed disk SKU for the app data disks (the catalog binds P10/P15/P20/P30 by size; Premium_LRS tiers by size).", None,
  clouds=["azure"], twin="app_disk_type"),
 var("app_disk_type", "string", '"gp3"', ["data"], None, "EBS volume type for the app data volumes (P3-D13: gp3 everywhere; io2 for a provisioned-IOPS override).",
  ('contains(["gp3", "io2"], var.app_disk_type)', "app_disk_type must be gp3 or io2"),
  clouds=["aws"], twin="app_disk_sku"),
 var("nats_nodes", "number", "0", ["data", "app"], None, "NATS processes (Sizing nats_nodes): 0 embedded, 1 single, 3 cluster (two on the app nodes + one quorum VM).",
  ("contains([0, 1, 3], var.nats_nodes)", "nats_nodes must be 0, 1 or 3"),
  aws={"description": "NATS processes (Sizing nats_nodes): 0 embedded, 1 single, 3 cluster (two on the app nodes + one quorum instance)."}),
 var("nats_disk_gb", "number", "0", ["data"], None, "Per NATS node premium disk in GiB (Sizing nats_disk_gb); 0 when the log is embedded (it then lives on the app data disk).", None,
  aws={"description": "Per NATS node EBS volume in GiB (Sizing nats_disk_gb); 0 when the log is embedded (it then lives on the app data volume)."}),
 var("log", "string", None, ["data", "app"], None, "Catalog axis log: embedded | nats-single | nats-cluster.",
  ('contains(["embedded", "nats-single", "nats-cluster"], var.log)', "log must be embedded, nats-single or nats-cluster")),
 var("harness", "string", '"off"', ["data", "app"], None, "Catalog axis harness: off | on (harness-gateway runner containers; the data layer mints GATEWAY_TOKEN when on).",
  ('contains(["off", "on"], var.harness)', "harness must be off or on")),
 var("identity", "string", '"oidc"', ["data", "app"], None, "Catalog axis identity: oidc | saml | local (the data layer mints the SAML SP keypair when saml).",
  ('contains(["oidc", "saml", "local"], var.identity)', "identity must be oidc, saml or local")),
 var("tls_certificate_secret_id", "string", '""', ["app"], None, "Key Vault secret id of a customer-provided PFX for the public hostname - versionless https://<vault>.vault.azure.net/secrets/<name> (recommended, tracks rotation) or versioned .../secrets/<name>/<version>; a bare secret name in the deployment's own vault is accepted for compatibility. Empty = ACME per var.acme.", None,
  clouds=["azure"], twin="tls_certificate_secret_arn"),
 var("tls_certificate_secret_arn", "string", '""', ["app"], None, "Secrets Manager secret ARN of a customer-provided PFX for the public hostname, terminated by the HAProxy pair (haproxy-pair; DEP-2 twin) or by Caddy on a single node. Empty = ACME per var.acme.", None,
  clouds=["aws"], twin="tls_certificate_secret_id"),
 var("tls_certificate_arn", "string", '""', ["app"], ["appliance"], "ACM certificate ARN for the Application Load Balancer (managed-l7): an ACM-imported customer certificate, or an ACM-issued one via Route 53 DNS validation when route53_zone_id is set. Empty on every other l7.", None,
  clouds=["aws"], twin=None),
 # ---- appliance data ----
 var("postgres", "string", None, ["data", "app"], ["appliance"], "Catalog axis postgres: managed-single | managed-ha | self-hosted-separate | existing.",
  ('contains(["managed-single", "managed-ha", "self-hosted-separate", "existing"], var.postgres)', "postgres must be managed-single, managed-ha, self-hosted-separate or existing")),
 var("pg_sku", "string", '""', ["data"], ["appliance"], "Flexible Server sku_name (catalog provision name, e.g. MO_Standard_E4ds_v5) for managed-*; empty otherwise.", None,
  clouds=["azure"], twin="pg_instance_class"),
 var("pg_instance_class", "string", '""', ["data"], ["appliance"], "RDS instance class (catalog provision name, e.g. db.m6g.xlarge) for managed-*; empty otherwise.", None,
  clouds=["aws"], twin="pg_sku"),
 var("pg_vm_size", "string", '""', ["data"], ["appliance"], "VM size (catalog provision name, e.g. Standard_E4as_v5) for self-hosted-separate; empty otherwise.", None,
  clouds=["azure"], twin="pg_instance_type"),
 var("pg_instance_type", "string", '""', ["data"], ["appliance"], "EC2 instance type (catalog provision name, e.g. r6a.xlarge) of the PostgreSQL instance for self-hosted-separate; empty otherwise.", None,
  clouds=["aws"], twin="pg_vm_size"),
 var("pg_instances", "number", "1", ["data"], ["appliance"], "Sizing pg_instances: 1, or 2 = a streaming replica VM (self-hosted) / ZoneRedundant HA (managed-ha).",
  ("contains([1, 2], var.pg_instances)", "pg_instances must be 1 or 2"),
  aws={"description": "Sizing pg_instances: 1, or 2 = a streaming replica instance (self-hosted) / Multi-AZ (managed-ha)."}),
 var("pg_disk_gb", "number", "0", ["data"], ["appliance"], "PostgreSQL provisioned storage in GiB (Sizing pg_disk_gb): Flexible Server storage_mb, or the PostgreSQL VM data disk.", None,
  aws={"description": "PostgreSQL provisioned storage in GiB (Sizing pg_disk_gb): RDS allocated_storage (gp3), or the PostgreSQL instance's EBS data volume."}),
 var("pg_backup_retention_days", "number", "35", ["data"], ["appliance"], "Flexible Server backup retention (plan 4.4: 35 days of PITR); the self-hosted job uses the same number.",
  ("var.pg_backup_retention_days >= 7 && var.pg_backup_retention_days <= 35", "pg_backup_retention_days must be 7..35"),
  aws={"description": "RDS backup_retention_period (plan 4.4: 35 days of PITR); the self-hosted job uses the same number."}),
 var("app_layout", "string", '"single"', ["data", "app"], ["appliance"], "Catalog axis app_layout: single (RA-2) | ha (RA-3).",
  ('contains(["single", "ha"], var.app_layout)', "app_layout must be single or ha")),
 # ---- app ----
 var("hostname", "string", None, ["app"], None, "Public HTTPS hostname of the dashboard (external_url = https://<hostname>).",
  ('can(regex("^[a-z0-9.-]+\\\\.[a-z]{2,}$", lower(var.hostname))) && !startswith(lower(var.hostname), "changeme")', "hostname must be a DNS name and not the CHANGEME placeholder")),
 var("dns_zone_name", "string", '""', ["app"], None, "Existing Azure DNS zone to create the A record in (data source, never created); empty = no record, the public IP is an output.", None,
  clouds=["azure"], twin="route53_zone_id"),
 var("dns_zone_resource_group", "string", '""', ["app"], None, "Resource group of dns_zone_name.", None,
  clouds=["azure"], twin="route53_zone_id"),
 var("route53_zone_id", "string", '""', ["app"], None, "Existing Route 53 hosted zone id to create the A record in (data source, never created); empty = no record, the public IP is an output.", None,
  clouds=["aws"], twin="dns_zone_name + dns_zone_resource_group"),
 var("admin_cidr", "list(string)", None, ["app"], None, "Source CIDRs allowed to SSH (port 22) to the VMs; [] = no SSH rule at all (Bastion or serial console are the customer's choice).", None,
  aws={"description": "Source CIDRs allowed to SSH (port 22) to the public-subnet instances; [] = no SSH rule at all (SSM Session Manager is the documented operator path on every AWS shape, P3-D10)."}),
 var("monitoring_cidr", "list(string)", "[]", ["app"], None, "Source CIDRs allowed to scrape /metrics (:9464); [] = the metrics listener is not opened.", None),
 var("l7", "string", None, ["app"], None, "Catalog axis l7: caddy-on-box (single node) | haproxy-pair | managed-l7.",
  ('contains(["caddy-on-box", "haproxy-pair", "managed-l7"], var.l7)', "l7 must be caddy-on-box, haproxy-pair or managed-l7")),
 # The SAME name a second time, on a disjoint (cloud x shape x layer) cell: the AWS
 # appliance DATA root reads l7 too (R-02: the RDS / PostgreSQL EC2 :5432 sources key
 # on the same caddy-on-box predicate the app root uses). assert_disjoint_names pins
 # that no root ever renders one name twice.
 var("l7", "string", None, ["data"], ["appliance"], "Catalog axis l7: caddy-on-box (single node) | haproxy-pair | managed-l7 - on the data layer it decides which subnets may open :5432 (the app node is public exactly when Caddy sits on the box; R-02).",
  ('contains(["caddy-on-box", "haproxy-pair", "managed-l7"], var.l7)', "l7 must be caddy-on-box, haproxy-pair or managed-l7"),
  clouds=["aws"]),
 var("acme", "string", '"http01"', ["app"], None, "Certificate issuance when tls_certificate_secret_id is empty: http01 (Caddy, single node) | dns01 (certbot via the VM identity on the HAProxy pair) | off.",
  ('contains(["http01", "dns01", "off"], var.acme)', "acme must be http01, dns01 or off"),
  aws={"description": "Certificate issuance when tls_certificate_secret_arn is empty: http01 (Caddy, single node) | dns01 (certbot via the instance role on the HAProxy pair) | off."}),
 var("acme_staging", "bool", "false", ["app"], None, "Use the Let's Encrypt staging directory (test runs; avoids rate limits).", None),
 var("app_vm_size", "string", None, ["app"], None, "App VM size (catalog provision name, e.g. Standard_D4as_v5).", NOT_CHANGEME("app_vm_size"),
  clouds=["azure"], twin="app_instance_type"),
 var("app_instance_type", "string", None, ["app"], None, "App EC2 instance type (catalog provision name, e.g. m6a.xlarge).", NOT_CHANGEME("app_instance_type"),
  clouds=["aws"], twin="app_vm_size"),
 var("nats_replicas", "number", "1", ["app"], None, "[log].replicas rendered into config (Sizing nats_replicas).", ("var.nats_replicas >= 1 && var.nats_replicas <= 5", "nats_replicas must be 1..5")),
 var("nats_max_age_hours", "number", "24", ["app"], None, "[log].max_age_hours (Sizing nats_max_age_hours).", None),
 var("nats_max_bytes_gb", "number", "10", ["app"], None, "[log].max_bytes_gb (Sizing nats_max_bytes_gb).", None),
 # C-L (demo-estate rebuild plan 2026-09-20): lb_nodes = 1 is a SUPPORTED, uncertified hand-fill on Azure
 # (the planner renders 2 for haproxy-pair) - ONE HAProxy VM behind the Standard LB, so a -replace, a
 # reboot or a failed box is a full outage until the new VM's first boot completes (README "One HAProxy
 # VM"). AWS keeps its [0, 2] validation: its haproxy-pair child still hard-codes the pair.
 var("lb_nodes", "number", "0", ["app"], ["appliance"], "HAProxy VMs (Sizing lb_nodes): 2 for haproxy-pair (the certified pair; the planner renders 2), 1 = ONE HAProxy VM behind the Standard LB (supported, hand-filled: a -replace / reboot / failed box is a full outage until the new VM's first boot completes), else 0.", ("contains([0, 1, 2], var.lb_nodes)", "lb_nodes must be 0, 1 or 2"),
  aws={"description": "HAProxy instances (Sizing lb_nodes): 2 for haproxy-pair, else 0.", "validation": ("contains([0, 2], var.lb_nodes)", "lb_nodes must be 0 or 2")}),
 # C-N (demo-estate rebuild plan 2026-09-20, section 5): where a nats-single broker runs. "dedicated" =
 # the nats-quorum child as a standalone broker (node_index 0, no peers, the quorum disk) and the app
 # node(s) as pure clients (ctx nats_colocated = false, nats_disk_lun -1, nats_peers = [the VM]).
 # Azure only: the AWS roots have no placement notion yet (their app root still colocates).
 var("nats_placement", "string", '"colocated"', ["data", "app"], ["appliance"], "Where a nats-single broker runs: colocated (on app node 0, today's behaviour) or dedicated (its own small VM, the catalog's nats-single text). Ignored on embedded; refused with nats_nodes = 3.", ("contains([\"colocated\", \"dedicated\"], var.nats_placement)", "nats_placement must be colocated or dedicated"),
  clouds=["azure"]),
 # D26 (2026-09-19): behind the L7 layouts NO VM carries a public IP (the HAProxy pair sits behind
 # the Standard LB, which fronts 443/80 only), so an operator has no SSH path at all and lives on
 # `az vm run-command invoke`. Opt-in, app layer, appliance only (a compact VM has its own public
 # IP). Port rule: LB inbound NAT rule i = public frontend port 2200+i -> :22 on HAProxy VM i;
 # scoped by the existing admin_cidr NSG row (destination port 22 + the operator's source address,
 # so the NAT'd flow matches allow-ssh-admin unchanged) - refused with admin_cidr = [] and on any l7
 # but haproxy-pair. Other VMs: ProxyJump through the pair (same user + key everywhere, C1b
 # vm_ssh_public_key): ssh -J observer@<public_ip>:2200 observer@<app-private-ip>. D35: the jump
 # arrives FROM the lb subnet, so while the knob is on the app NSG's allow-ssh-admin row (and the
 # self-hosted PostgreSQL VM's allow-ssh-app row) admits the lb prefix beside admin_cidr - the
 # quorum VM sits in the app subnet and is covered by the app row. Azure only: P3-D10 rules NO
 # AWS twin (SSM Session Manager replaces the NAT-rule zoo).
 var("admin_ssh_via_lb", "bool", "false", ["app"], ["appliance"], "D26: opt-in SSH through the Standard LB to the HAProxy VMs, which carry no public IP: one inbound NAT rule per HAProxy VM i (public port 2200+i -> :22, TCP), admitted by the same admin_cidr NSG rule as direct SSH - so it is refused with admin_cidr = [] and on any l7 but haproxy-pair (managed-l7 has no HAProxy VM to NAT to). Reach the app / PostgreSQL / quorum nodes through the pair with ProxyJump: ssh -J observer@<public_ip>:2200 observer@<private-ip> (the same user and key on every VM) - while on, the app NSG's allow-ssh-admin row and the self-hosted PostgreSQL NSG's allow-ssh-app row also admit :22 from the lb subnet, the jump's source (D35). false = no NAT rule, admin_cidr alone on every SSH row; az vm run-command invoke stays the always-available fallback (Azure RBAC, ~30-60 s per call, runs as root, 4 KB output cap).", None,
  clouds=["azure"]),
 var("nat_per_az", "bool", "false", ["data"], ["appliance"], "P3-D9: one NAT gateway per availability zone for the private app subnets (three, priced) instead of the default single NAT gateway in AZ 1 that every private instance egresses through. The S3 gateway endpoint carries SoR / backup / bundle traffic either way.", None,
  clouds=["aws"]),
 var("small_vm_size", "string", '"Standard_B2ms"', ["app"], None, "VM size for the quorum and HAProxy VMs; override in regions where B2ms is capacity-restricted.", None,
  clouds=["azure"], twin="small_instance_type"),
 var("small_instance_type", "string", '"t3.large"', ["app"], None, "EC2 instance type for the quorum and HAProxy instances (P3-D13).", None,
  clouds=["aws"], twin="small_vm_size"),
 var("harness_runners", "number", "0", ["app"], None, "harness-gateway runner containers on the app nodes (Sizing harness_runners).", None),
 var("retention_days", "number", "365", ["app"], None, "[server].data_retention_days (catalog axis retention).", ("contains([90, 180, 365, 730], var.retention_days)", "retention_days must be 90, 180, 365 or 730")),
 var("image_tag", "string", None, ["app"], None, "Release tag of observer-org / observer-postgres / harness-gateway (stamped by the planner from the binary's own version).", NOT_CHANGEME("image_tag")),
 var("registry", "string", None, ["app"], None, "Image registry host: superbasedenterprise.azurecr.io (vendor-private) or the customer mirror.", NOT_CHANGEME("registry")),
 var("bundle_dir", "string", '"."', ["app"], None, "Local path of the rendered bundle directory (config.production.toml, docker-compose*.yaml, nats.conf, ...) the app layer uploads to the private bundle container.", None,
  aws={"description": "Local path of the rendered bundle directory (config.production.toml, docker-compose*.yaml, nats.conf, ...) the app layer uploads to the private bundle prefix s3://<bucket>/bundle/ (P3-D5: beside the on-box scripts the first boot fetches)."}),
 var("data_state", "object({ storage_account_name = string, container_name = string, key = string })", None, ["app"], None,
  "Where the data layer's state lives (rendered into terraform/app.tfvars from bootstrap's outputs); read with terraform_remote_state.", None,
  aws={"type": "object({ bucket = string, key = string, region = string })"}),
]


def for_cloud(v, cloud):
    """The row as ONE cloud sees it: base fields with that cloud's overrides applied."""
    r = dict(v)
    r.update(v["overrides"].get(cloud, {}))
    return r


def on_cloud(v, cloud):
    return v["clouds"] is None or cloud in v["clouds"]


def applies(v, cloud, layer, shape):
    return on_cloud(v, cloud) and layer in v["layers"] and (v["shapes"] is None or shape in v["shapes"])


def cells(v):
    """The (cloud, shape, layer) roots a row renders into."""
    return {(c, s, l) for c in CLOUDS if on_cloud(v, c)
            for s in SHAPES if v["shapes"] is None or s in v["shapes"]
            for l in v["layers"]}


def assert_disjoint_names(rows):
    """A name may appear on several rows (l7: the app layer on both clouds, and
    the AWS appliance data layer) only when their root sets are disjoint - one
    root never declares a variable twice, and the C1 tables stay unambiguous."""
    seen = {}
    for v in rows:
        for cell in cells(v):
            prev = seen.setdefault((v["name"], cell), v)
            assert prev is v, f"variable {v['name']!r} is declared twice for {cell}"


def hcl_string(s):
    return '"' + s.replace('\\', '\\\\').replace('"', '\\"') + '"'


def render_variables(cloud, layer, shape):
    out = [f"""# GENERATED by scripts (deploy/modules/CONTRACT.md is the source of truth for
# this table; the Go test render/tfvars_test.go reads THIS file to learn which
# variables the layer declares). Add a variable to CONTRACT.md's table and
# regenerate; do not hand-edit. Phase 2 plan contract C1.
#
# Root: deploy/modules/{shape}/{cloud}/{layer}
"""]
    for v in V:
        if not applies(v, cloud, layer, shape):
            continue
        r = for_cloud(v, cloud)
        out.append(f'variable "{r["name"]}" {{')
        out.append(f'  type        = {r["type"]}')
        if r["default"] is not None:
            out.append(f'  default     = {r["default"]}')
        out.append('  description = ' + hcl_string(r["description"]))
        if r["validation"]:
            cond, msg = r["validation"]
            out.append('  validation {')
            out.append(f'    condition     = {cond}')
            out.append('    error_message = ' + hcl_string(msg))
            out.append('  }')
        out.append('}\n')
    return "\n".join(out)


VERSIONS = {
 "azure": """# Provider pins shared by every Phase 2 root (plan contract C1; DR-15: valid
# for Terraform >= 1.9 and OpenTofu >= 1.8, tested on OpenTofu).
terraform {
  required_version = ">= 1.9.0"
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 4.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.6"
    }
    tls = {
      source  = "hashicorp/tls"
      version = "~> 4.0"
    }
    time = {
      source  = "hashicorp/time"
      version = "~> 0.12"
    }
  }
}
""",
 "aws": """# Provider pins shared by every Phase 3 AWS root (plan contract C1; DR-15:
# tested on OpenTofu). >= 1.10 because the S3 backend's use_lockfile (P3-D11,
# the lock without a DynamoDB table) exists from Terraform 1.10 / OpenTofu 1.10.
terraform {
  required_version = ">= 1.10.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.6"
    }
    tls = {
      source  = "hashicorp/tls"
      version = "~> 4.0"
    }
    time = {
      source  = "hashicorp/time"
      version = "~> 0.12"
    }
  }
}
""",
}

BACKEND = {
 "azure": """# Partial backend configuration (plan P2-D10): the storage account, container
# and key arrive from terraform/backend-<layer>.hcl, rendered by the planner
# from the bootstrap layer's outputs:
#   tofu init -backend-config=../../../../terraform/backend-%s.hcl
# use_azuread_auth = true so no storage key is needed on the operator's machine.
terraform {
  backend "azurerm" {
    use_azuread_auth = true
  }
}
""",
 "aws": """# Partial backend configuration (plan P3-D11): the bucket, key
# (observer-org/<set>/<layer>.tfstate) and region arrive from
# terraform/backend-<layer>.hcl, rendered by the planner from the bootstrap
# layer's outputs:
#   tofu init -backend-config=../../../../terraform/backend-%s.hcl
# use_lockfile = true (S3 conditional writes) is the lock - no DynamoDB table;
# the applying principal's own credentials (AWS_PROFILE / env / SSO) sign it.
terraform {
  backend "s3" {
    use_lockfile = true
    encrypt      = true
  }
}
""",
}


def render_tree():
    """Every generated file as {repo-relative path: content}."""
    files = {}
    for cloud in CLOUDS:
        for shape in SHAPES:
            for layer in LAYERS:
                d = os.path.join("deploy", "modules", shape, cloud, layer)
                files[os.path.join(d, "variables.tf")] = render_variables(cloud, layer, shape)
                files[os.path.join(d, "versions.tf")] = VERSIONS[cloud]
                if layer != "bootstrap":
                    files[os.path.join(d, "backend.tf")] = BACKEND[cloud] % layer
    files[os.path.join("deploy", "modules", "CONTRACT.md")] = render_contract()
    return files


def cell(s):
    return s.replace("|", "\\|")


def table(rows, cloud=None, twin_header=None):
    """One C1 table. cloud=None renders the base (core) fields and flags rows that
    carry a per-cloud override; a cloud renders that cloud's view. twin_header adds
    the documentation-only twin column for a cloud-only appendix."""
    head = ["Variable", "Type", "Default", "Layers", "Shapes", "Description"] + ([twin_header] if twin_header else [])
    out = ["| " + " | ".join(head) + " |", "|" + "---|" * len(head)]
    for v in rows:
        r = for_cloud(v, cloud) if cloud else v
        desc = r["description"] + (" Validated." if r["validation"] else "")
        if cloud is None and v["overrides"]:
            desc += " Per-cloud override: " + ", ".join(sorted(v["overrides"])) + " (see that cloud's C1 appendix)."
        line = [f"`{r['name']}`", f"`{r['type']}`", 'required' if r["default"] is None else '`' + r["default"] + '`',
                ", ".join(r["layers"]), 'both' if r["shapes"] is None else ", ".join(r["shapes"]), cell(desc)]
        if twin_header:
            line.append(f"`{v['twin']}`" if v["twin"] else "none")
        out.append("| " + " | ".join(line) + " |")
    return "\n".join(out)


def override_lines(cloud):
    """One line per per-cloud override of a core row, for that cloud's appendix."""
    out = []
    for v in V:
        o = v["overrides"].get(cloud)
        if not o:
            continue
        parts = []
        for k in ("type", "default", "description", "validation"):
            if k not in o:
                continue
            val = o[k]
            if k == "validation":
                val = "none" if val is None else f"`{val[0]}` ({val[1]})"
            elif k in ("type", "default"):
                val = f"`{val}`"
            parts.append(f"{k} = {cell(val)}")
        out.append(f"- `{v['name']}`: " + "; ".join(parts))
    return "\n".join(out)


def render_contract():
    core = [v for v in V if v["clouds"] is None]
    az_only = [v for v in V if v["clouds"] == ["azure"]]
    aws_only = [v for v in V if v["clouds"] == ["aws"]]
    return (CONTRACT
            .replace("@@TABLE@@", table(core))
            .replace("@@AZURE_TABLE@@", table(az_only, "azure", "AWS twin"))
            .replace("@@AWS_TABLE@@", table(aws_only, "aws", "Azure twin"))
            .replace("@@AWS_OVERRIDES@@", override_lines("aws"))
            .replace("@@AZURE_OVERRIDES@@", override_lines("azure") or "- none: the base wording of every core row is the Azure wording"))


def write_tree(files):
    for rel, content in files.items():
        p = os.path.join(REPO, rel)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "w") as f:
            f.write(content)
    # The AWS roots' main.tf / outputs.tf are owned by the wave agents and
    # never written here; the directories exist so a fresh checkout has the
    # skeleton in place (a missing main.tf is theirs to add, not ours to clobber).
    print("generated", ROOT)


def check_tree(files):
    drift = []
    for rel, want in sorted(files.items()):
        p = os.path.join(REPO, rel)
        if not os.path.isfile(p):
            drift.append(f"{rel}: MISSING (run scripts/gen-module-stubs.py)")
            continue
        with open(p) as f:
            got = f.read()
        if got != want:
            diff = "".join(difflib.unified_diff(got.splitlines(True), want.splitlines(True), f"tree/{rel}", f"generated/{rel}"))
            drift.append(f"{rel}: DIFFERS from the generator\n{diff}")
    if drift:
        print("gen-module-stubs --check: the generated tree drifted from scripts/gen-module-stubs.py", file=sys.stderr)
        for d in drift:
            print(d, file=sys.stderr)
        return 1
    print(f"gen-module-stubs --check: {len(files)} generated files identical to the table")
    return 0


def main(argv):
    assert_disjoint_names(V)
    files = render_tree()
    if "--check" in argv:
        return check_tree(files)
    write_tree(files)
    return 0


CONTRACT = """# Module contracts (the stub every wave agent codes against)

Plans of record: `docs/plans/enterprise-deployment-phase-2-implementation-plan-2026-09-18.md`
(section 5, contracts C1-C6; every decision P2-D1..P2-D18 RULED 2026-09-18) for the Azure roots,
and `docs/plans/enterprise-deployment-phase-3-implementation-plan-2026-09-19.md` (section 5,
C1-aws / C1b-aws / C3-aws / C10; P3-D1..P3-D16 RULED 2026-09-19) for the AWS roots. This file
is the rendered form of the ONE variable table that lives in `scripts/gen-module-stubs.py`,
which regenerates every root's `variables.tf`, `versions.tf`, `backend.tf` AND this file for
BOTH clouds (P3-D2: every row carries `clouds` plus per-cloud overrides of type / default /
description / validation). Edit the script's table, re-run it, commit both;
`python3 scripts/gen-module-stubs.py --check` is the CI identity gate. A variable that is not in
this table does not exist.

## Layout (P2-D1, P2-D10, P3-D1)

```
deploy/modules/
  CONTRACT.md                      this file
  README.md                        operator-facing: what the roots are, apply order, teardown
  _shared/cloudinit/files/         the cloud-generic on-box files, ONE owner for both clouds (P3-D1 / DR-62):
                                   observer-first-boot.sh + .service, observer-env-sync.{service,timer},
                                   observer-haproxy-drain.sh, support-bundle.sh, restore-drill.sh,
                                   bootstrap-haproxy.sh, Caddyfile / haproxy.cfg / nats.conf .tftpl, the three
                                   role compose files, the six pgbackrest-{full,diff,check}.{service,timer} units.
                                   Azure INLINES them into its templates (check-sync.sh keeps the copies byte-
                                   identical); AWS fetches them from the bundle prefix at first boot (P3-D5)
  _shared/azure/<child>/           child modules (main.tf, variables.tf, outputs.tf, versions.tf)
     network/      VNet, subnets (app, data [delegated to Flexible Server], lb), private DNS zone   [data layer]
     keyvault/     Key Vault (RBAC, purge protection), the generated secrets, role assignments     [data layer]
     storage/      SoR storage account + observer-archive + bundle containers, firewall, SAS      [data layer]
     app-vm/       one --role all VM: NIC, identity, cloud-init, data-disk attachment            [app layer]
     dns/          A record in the customer's zone                                                [app layer]
     backup/       Recovery Services vault + daily VM backup policy (RA-0 local-disk durability)  [app layer]
     postgres-flexible/  Flexible Server single / ZoneRedundant, private access                   [data layer, appliance]
     postgres-vm/  PostgreSQL VM (observer-postgres image + pgBackRest job), optional replica      [data layer, appliance]
     nats-quorum/  the third NATS VM                                                               [app layer, appliance ha]
     haproxy-pair/ two HAProxy VMs                                                                 [app layer, appliance ha]
     lb/           Azure Standard Load Balancer + public IP + probe (fronts the HAProxy pair)      [app layer, appliance ha]
     appgw/        Application Gateway v2 (managed-l7)                                            [app layer, appliance]
     cloudinit/    *.yaml.tftpl templates + files/ (the Azure-bound scripts: observer-bundle-fetch.sh,
                   observer-env-sync.sh, observer-copy-sealing-key.sh, observer-pgbackrest.sh,
                   pgbackrest.conf.tftpl, bootstrap-{app,pg,nats-quorum}.sh, check-sync.sh, test-scripts.sh)
  _shared/aws/<child>/             child modules (main.tf, variables.tf, outputs.tf, versions.tf)
     network/      VPC, subnets (public, app, db per AZ), IGW, NAT gateway(s), S3 gateway endpoint  [data layer]
     secrets/      Secrets Manager secrets observer-org/<name_prefix>/<name>, the sealing key       [data layer]
     storage/      the ONE SoR bucket <name_prefix>-sor (keys at the bucket root; bundle/ and
                   pg-backup/ prefixes; observer-archive/ reserved, unused)                        [data layer]
     app-instance/ one --role all EC2 instance: profile, user-data stub, EBS volume attachment       [app layer]
     dns/          Route 53 A record in the customer's zone                                          [app layer]
     backup/       AWS Backup plan: daily EBS snapshots, retention_days                              [app layer]
     rds/          RDS PostgreSQL 16 single-AZ / Multi-AZ, DB subnet group                           [data layer, appliance]
     postgres-ec2/ PostgreSQL EC2 instance (observer-postgres image + pgBackRest to S3)              [data layer, appliance]
     nats-quorum/  the third NATS instance                                                           [app layer, appliance ha]
     haproxy-pair/ two HAProxy instances                                                             [app layer, appliance ha]
     nlb/          Network Load Balancer, TCP 443/80 passthrough, one EIP per AZ                     [app layer, appliance ha]
     alb/          Application Load Balancer + ACM certificate (managed-l7)                          [app layer, appliance]
     cloudinit/    *.userdata.tftpl stubs (the ONLY thing in user_data) + files/ (the AWS-variant
                   scripts) - owned by A2, see C3-aws
  compact/azure/{bootstrap,data,app}/     roots for RA-0 / RA-1a / RA-1b
  appliance/azure/{bootstrap,data,app}/   roots for RA-2 (single) / RA-3 (ha)
  compact/aws/{bootstrap,data,app}/       roots for RA-0 / RA-1a / RA-1b on AWS
  appliance/aws/{bootstrap,data,app}/     roots for RA-2 (single) / RA-3 (ha) on AWS
```

**Layer homes (refined during wave A, a contract deviation from P2-D10's parenthetical):**
the VNet, subnets and private DNS zone live in the **data** layer, not app - a Flexible
Server with private access requires its delegated subnet at creation, and a VNet is a pet
(replacing it destroys everything attached). NSGs, NICs, public IPs, VMs, LBs, App Gateway,
DNS records and backup policies are the app layer's. The PostgreSQL VM (self-hosted-separate)
lives WHOLE in the data layer (its data disk is the pet; `tofu apply -replace` rebuilds the VM).
The bootstrap layer grants the applying principal `Storage Blob Data Contributor` on the state
account (`azurerm_role_assignment.state_blob_contributor`, scope = the `state_storage_account_id`
output) because the rendered data/app backends authenticate with Azure AD (`use_azuread_auth`).
The AWS roots keep the same homes: the VPC, subnets, NAT and S3 endpoint, the secrets, the SoR
bucket, the RDS instance / PostgreSQL EC2 instance and every EBS pet volume are the data layer's;
security groups, EIPs, instances, the NLB / ALB, the Route 53 record and the AWS Backup plan
are the app layer's (P3-D6..P3-D9).

## C1 core root-module variables (both clouds)

Every row below exists on BOTH clouds under the same name, type, default, layers and shapes;
the renderer keys on these names. A row marked "Per-cloud override" renders with that cloud's
wording (or, for `data_state`, that cloud's type) - the exact override is listed in the
cloud's appendix.

@@TABLE@@

Rules: no `developers` variable anywhere; every quantity above is copied from
`AnswerSet.Sizing` by the planner (`render.Files` -> `terraform/<layer>.tfvars`), every SKU
name from the catalog's `provision` field; `validation` blocks refuse `CHANGEME`; no variable
is `sensitive` because no secret is ever a variable.

## C1-azure appendix (Azure-only variables)

@@AZURE_TABLE@@

Base wording of the core rows on Azure:

@@AZURE_OVERRIDES@@

## C1-aws appendix (AWS-only variables)

@@AWS_TABLE@@

No `storage_replication` twin (S3 is regionally redundant; the planner renders nothing and
`deploy grow` has no axis to hold), no `admin_ssh_via_lb` twin (P3-D10: SSM Session Manager),
no `state_container_name` twin (the S3 state bucket `<name_prefix>-tfstate` holds the layer
keys directly, P3-D11).

Per-cloud overrides of core rows on AWS (everything not listed renders the base wording):

@@AWS_OVERRIDES@@

## Azure (C1b, C3, C7, C8, C9 - the Phase 2 contracts, unchanged)

### C1b data -> app outputs (read through `terraform_remote_state`)

| Output | Type | Meaning |
|---|---|---|
| `resource_group_name` | string | the deployment's resource group (created by bootstrap, echoed) |
| `vnet_id`, `subnet_ids` | string, map(string) | `app`, `data`, `lb` subnet ids |
| `key_vault_id`, `key_vault_uri` | string | the vault the VMs read |
| `secret_names` | map(string) | logical -> Key Vault secret name: `session-key`, `bearer-signing-key`, `policy-signing-key`, `scim-token`, `nats-password`, `pg-app-password`, `pg-control-dsn`, `pg-data-dsn`, `sealing-key`, `object-sas`, `acr-pull-user`, `acr-pull-token`, `nats-ca`, `nats-cert-<i>`, `nats-key-<i>`, `pg-server-cert`, `pg-server-key`, `pg-ca`, `harness-gateway-token`, `saml-sp-cert`, `saml-sp-key` (absent keys = not minted for this answer set) |
| `sealing_key_secret_id` | string | the plan's output, echoed by app |
| `vm_ssh_public_key` | string | the admin user's public key (customer-provided or generated) |
| `storage_account_name`, `archive_container_name`, `bundle_container_name`, `bundle_container_url` | string | the SoR account and the two containers |
| `nats_disk_gb` | number | D31: the per-node NATS disk size in GiB (Sizing nats_disk_gb; 0 when the log is embedded) - the app layer renders it as the brokers' JetStream `max_file_store: <n>GB` (ctx `nats_max_file_store`, the planner's own bundle rule) and refuses at plan time a `nats_max_bytes_gb` stream cap larger than it |
| `bundle_container_id` | string | the bundle container's resource-manager id (`/subscriptions/.../blobServices/default/containers/bundle`) - what `azurerm_storage_blob.storage_container_id` takes (azurerm 4.x parses 12 segments; D6). `bundle_container_url` stays the data-plane address for cloud-init's bundle fetch (C3); the two are not interchangeable |
| `object_sas_expires_at` | string (RFC 3339) | when the minted SAS expires |
| `app_data_disk_ids` | list(string) | one per app node, attached by app-vm at LUN 0 |
| `nats_quorum_disk_id` | string | empty unless nats_nodes = 3 or nats_placement = dedicated (C-N: the dedicated nats-single broker's disk is this resource) |
| `postgres_endpoint` | string | host[:port] of the control/data database (managed: the Flexible Server's public FQDN `<name_prefix>-pg.postgres.database.azure.com`, never `<server>.<private zone>` - D20; the PG VM's private IP; or empty for `existing`) |
| `postgres_ca_secret_name` | string | Key Vault secret holding the CA the client verifies (`verify-full`) |
| `app_private_ips` | list(string) | the PLANNED static private IP per app node (`cidrhost(app subnet, 10 + index)`); the app layer assigns exactly these to the NICs and the data layer puts them in the NATS cert SANs - ONE derivation, in data (wave-A fold of A1's open question 1) |
| `app_subnet_prefix` | string | the app subnet CIDR (for trusted_proxies / NSG rules) |
| `vnet_address_space` | string | the VNet's address space (`10.60.0.0/16` by default): the app NSG's `allow-metrics` row admits it beside `monitoring_cidr` so an in-VNet scraper on any subnet reaches `:9464` (the listener binds the app node's PRIVATE IP behind the LB - no LB rule or NAT reaches it from `monitoring_cidr`'s public source). Absent on a data state written before wave R-A: the app layer falls back to the app subnet only until the data layer is re-applied |
| `nats_urls` | list(string) | rendered by app once the VMs' private IPs are known; data outputs the planned private IPs for the static-IP NICs |

### C3 cloud-init contract (A2 owns the templates; A1/B1 call `templatefile`)

Every `deploy/modules/_shared/azure/cloudinit/<role>.yaml.tftpl` takes ONE object `ctx`:

```hcl
ctx = {
  role                 = "app" | "pg" | "nats-quorum" | "haproxy"
  hostname             = string          # public hostname (app, haproxy)
  node_index           = number          # 0-based within the role
  bundle_container_url = string          # https://<acct>.blob.core.windows.net/bundle
  key_vault_url        = string          # https://<vault>.vault.azure.net/
  secret_names         = map(string)     # C1b's map
  image_tag            = string
  registry             = string
  postgres_mode        = "colocated" | "separate" | "managed" | "existing"
  log_mode             = "embedded" | "nats-single" | "nats-cluster"
  nats_peers           = list(string)    # private IPs of the other NATS nodes (routes)
  nats_replicas        = number
  acme                 = "http01" | "dns01" | "off"
  acme_staging         = bool
  metrics_listen       = string          # "" = off, else "<private-ip>:9464" - the HOST endpoint; the org binds :9464 inside the container and compose publishes it (D19)
  app_disk_lun         = number          # data disk LUN (mounted at /var/lib/observer-docker, docker's data-root)
  pg_disk_lun          = number          # pg role only
  nats_disk_lun        = number          # -1 when the log store lives on the app disk; >= 0 = the app role's NATS disk, mounted at /var/lib/observer-nats with /var/lib/observer-nats/jetstream as the nats service's /data bind (CD-1)
  nats_colocated       = bool            # C-N: false ONLY on the app role when nats_placement = dedicated (the broker is the nats-quorum VM; first boot skips the step-1b nats.conf overwrite, writes [log].url = the peer(s) only, and env-sync scopes the NATS TLS material "org" - no nats member to restart); true everywhere else, and an ABSENT key reads as true (compact / AWS ctx)
  nats_max_file_store  = string          # D31: "<nats_disk_gb>GB" = the brokers' JetStream max_file_store (C1b nats_disk_gb, the planner's bundle rule); "" when embedded; ABSENT on compact (single broker on the app disk) - the template falls back to its LUN-keyed 20GB/10GB only then
  harness_runners      = number
  l7                   = "caddy-on-box" | "haproxy-pair" | "managed-l7"
  tls_certificate_secret_id = string  # "" = ACME per acme; else the C1 Key Vault secret ID of the customer PFX - versionless https://<vault>.vault.azure.net/secrets/<name> (recommended, tracks rotation) or versioned; a bare secret name in key_vault_url is accepted (P2-D5, D22)
  backend_ips          = list(string)    # haproxy role: the app nodes' private IPs (= C1b app_private_ips); [] on other roles
  object_account_name  = string          # C8: OBSERVER_OBJECT_ACCOUNT_NAME ("" when object_store = local-disk)
  object_container     = string          # C8: OBSERVER_OBJECT_CONTAINER ("observer-archive" or "")
  trusted_proxy_cidr   = string          # C9: the CIDR written into [server].trusted_proxies ("" = leave commented)
}
```

**Template escaping rule:** a `.tftpl` is rendered by `templatefile`, so every literal `${...}`
that belongs to bash (or compose) inside an inlined script MUST be written `$${...}` (and a
literal `%{` as `%%{`). `check-sync.sh` compares the UNESCAPED `files/*` copy against the
template after reversing that escape. A1/B1's `tofu test` on the app root renders the real
template, so an unescaped `${VAR}` fails THEIR gate, not only A2's.

The template installs docker (pinned apt), cosign (sha256-pinned script), the units under
`cloudinit/files/`, mounts LUN disks by `/dev/disk/azure/scsi1/lun<N>`, and enables
`observer-first-boot.service`, which: (1) fetches the bundle files with the VM identity
(IMDS -> Blob REST), (2) runs `observer-env-sync.sh` once (IMDS -> Key Vault REST -> `.env` +
`secrets/*`, 0600, uid 65532), (3) `docker login` with the pull token, `cosign verify` the
images, (4) `migrate --store all` once (app role, node_index 0 only), (5) `docker compose up
-d`. `observer-env-sync.timer` (6 h) re-runs (2) and restarts `org` only when a secret version
changed. No template line contains a secret; the ONLY reader of Key Vault on a box is
`observer-env-sync.sh`.

The rendered document itself reaches the VM as `custom_data = base64gzip(...)` (every VM child:
`app-vm`, `haproxy-pair`, and `postgres-vm` / `nats-quorum` through `app-vm`), never plain
`base64encode`, because Azure caps `osProfile.customData` at 64 KB raw / 87380 base64 characters
(D7) - the same cap DR-53 records for the bundle - and the app document alone is ~95 KB raw
(~126K plain-base64 characters) since it inlines every `files/*` script through `write_files`;
cloud-init decompresses gzip user-data transparently on the Azure datasource (Ubuntu 24.04).

### C7 `observer-postgres` image contract (A2 builds it; A3's compose override runs it)

`<registry>/observer-postgres:<tag>` = `FROM postgres:16.<minor>-bookworm` + Debian `pgbackrest`
(+ `curl`, `ca-certificates`); entrypoint and `postgres` uid (999) unchanged. The compose
override (A3) runs it as service `postgres` in project `observer-org-prod` with:

| Mount / env / arg | Value |
|---|---|
| `/var/lib/postgresql/data` | volume `org-postgres` (compact: on the app data disk) |
| `/etc/pgbackrest/pgbackrest.conf:ro` | `./secrets/pgbackrest.conf` (written by `observer-env-sync.sh`, holds the SAS: 0600) |
| `/etc/postgresql/tls/{server.crt,server.key,ca.crt}:ro` | `./secrets/pg-tls/*` (key 0600, owner uid 999) |
| `POSTGRES_USER` / `POSTGRES_DB` / `POSTGRES_PASSWORD` | `observer` / `observer_org` / `${OBSERVER_PG_APP_PASSWORD}` |
| `PGBACKREST_STANZA` | `observer` |
| `command` | `postgres -c ssl=on -c ssl_cert_file=/etc/postgresql/tls/server.crt -c ssl_key_file=/etc/postgresql/tls/server.key -c wal_level=replica -c archive_mode=on -c archive_command='pgbackrest --stanza=observer archive-push %p' -c max_wal_senders=10` |
| healthcheck | `pg_isready -U observer -d observer_org` |

Host timers (A2, `cloudinit/files/`) run `docker compose -f docker-compose.yaml -f
docker-compose.override.yaml exec -T postgres pgbackrest --stanza=observer [--type=full] backup`
from `/opt/observer-org` (never a hard-coded container name); `pgbackrest-check` runs `check`;
the first boot runs `stanza-create` once. `restore-drill.sh` restores the latest backup into a
scratch container (`observer-postgres` image, empty volume, `pgbackrest restore --delta`) and
starts a throwaway `observer-org serve` against it asserting `/readyz` 200. pgBackRest repo:
`repo1-type=azure`, `repo1-azure-account=<storage account>`, `repo1-azure-container=observer-archive`,
`repo1-path=/pg-backup`, `repo1-azure-key-type=sas`, `repo1-azure-key=<SAS>`,
`repo1-retention-full=5`, `repo1-retention-diff=35` (plan 4.4's 35 days), `process-max=2`.

**C7b org listener behind an L7 (ruling 2026-09-18, wave B):** the org server speaks PLAIN HTTP
on `:8443`; TLS ends at the L7. On `caddy-on-box` the base compose's `127.0.0.1:8443` publish
stands (Caddy shares the compose network and proxies to `org:8443`). On every other L7
(`haproxy-pair`, `managed-l7`) the compose OVERRIDE (A3, `render/files.go`) publishes
`8443:8443` on all interfaces and the NSG (B1) admits `:8443` only from the `lb` / `appgw`
subnets; HAProxy and Application Gateway speak plain HTTP to the app nodes (`server appN
<ip>:8443` with NO `ssl`, `backend_protocol = "Http"`), forward `X-Forwarded-For`, and the
first boot (C9) writes `trusted_proxies` = that subnet so audit rows record the real client.

### C8 what `observer-env-sync.sh` fills (A2 writes the script; A3 renders the placeholders)

The planner's `.env` and secret files keep `CHANGEME` placeholders; on a module-provisioned box
`observer-env-sync.sh` replaces EXACTLY the keys below (a key whose value is not `CHANGEME` is
left as rendered), from Key Vault (secret) or from the cloud-init `ctx` (non-secret):

| `.env` key or file | Source | Notes |
|---|---|---|
| `OBSERVER_CONTROL_STORE_DSN`, `OBSERVER_DATA_STORE_DSN` | Key Vault `pg-control-dsn`, `pg-data-dsn` | data layer composes them (`sslmode=verify-full&sslrootcert=/etc/observer-org/pg-tls/ca.crt` for self-hosted; the Microsoft RSA root for Flexible) |
| `OBSERVER_LOG_PASSWORD`, `NATS_PASSWORD` | Key Vault `nats-password` | the two are one secret |
| `OBSERVER_OBJECT_ACCOUNT_SAS` | Key Vault `object-sas` | the base compose does not pass this env; the override (A3) adds `OBSERVER_OBJECT_ACCOUNT_SAS: ${OBSERVER_OBJECT_ACCOUNT_SAS:-}` on `org` |
| `OBSERVER_OBJECT_ACCOUNT_NAME`, `OBSERVER_OBJECT_CONTAINER` | ctx (non-secret) | `object_store = cloud-bucket` only |
| `OBSERVER_ORG_SECRET_KEY` | Key Vault `sealing-key` | the env rail (`secretref.KeyEnv`); the override adds it to `org`'s environment; `sealing_key_path` stays in config but the env wins |
| `OBSERVER_PG_APP_PASSWORD` | Key Vault `pg-app-password` | compact (colocated) only |
| `OBSERVER_ORG_IMAGE`, `OBSERVER_POSTGRES_IMAGE`, `HARNESS_GATEWAY_IMAGE` | rendered by the planner (registry + tag) | never CHANGEME on the module path |
| `GATEWAY_TOKEN` | Key Vault `harness-gateway-token` | `harness = on` only |
| `secrets/session.key`, `secrets/bearer/signing.key`, `secrets/policy/signing.key`, `secrets/scim/token` | Key Vault `session-key`, `bearer-signing-key`, `policy-signing-key`, `scim-token` | 0600, uid 65532; `policy/signing.key` is the org's POLICY signing key (`[policy].signing_key_path` in the rendered config) - a different key from the bearer one; without it `GET /api/agent/budget` answers 409 `policy_channel_off` and every managed node's launch is refused |
| `secrets/saml/sp.crt`, `secrets/saml/sp.key` | Key Vault `saml-sp-cert`, `saml-sp-key` | `identity = saml` only |
| `secrets/pg-tls/{server.crt,server.key,ca.crt}` | Key Vault `pg-server-cert`, `pg-server-key`, `pg-ca` | self-hosted only; key owner uid 999 |
| `secrets/nats-tls/{ca.crt,node.crt,node.key}` | Key Vault `nats-ca`, `nats-cert-<i>`, `nats-key-<i>` | `nats-*` log only |
| `secrets/pgbackrest.conf` | template in `cloudinit/files/pgbackrest.conf.tftpl` + `object-sas` | self-hosted only |
| docker login | Key Vault `acr-pull-user`, `acr-pull-token` | never written to disk beyond docker's own config |

**`.env` reaches the box as part of the uploaded bundle** (the app role fetches it; the pg /
nats-quorum roles get a skeleton from cloud-init). The app layer's upload precondition REFUSES a
`bundle_dir/.env` in which any C8 secret key (`OBSERVER_CONTROL_STORE_DSN`,
`OBSERVER_DATA_STORE_DSN`, `OBSERVER_LOG_PASSWORD`, `NATS_PASSWORD`, `OBSERVER_OBJECT_ACCOUNT_SAS`,
`OBSERVER_OBJECT_ACCOUNT_KEY`, `OBSERVER_ORG_SECRET_KEY`, `OBSERVER_PG_APP_PASSWORD`, `GATEWAY_TOKEN`)
is set to anything but `CHANGEME` or empty - a hand-filled secret never leaves the operator's
machine through this path.

Every write is atomic (temp + rename), mode-checked, and the unit restarts `org` (and
`postgres` when its files changed) ONLY when a fetched secret's version differs from the one
recorded in `/var/lib/observer-env-sync/versions.json`.

### C9 first-boot config patch (A2's `observer-first-boot.service`; A3 keeps the keys present)

The planner renders `config.production.toml` before the infrastructure exists, so first boot
rewrites EXACTLY these keys from `ctx`, each with a `grep` assert after the edit (a miss is a
hard failure, never a silent skip):

| Key | Value | When |
|---|---|---|
| `[server].external_url` | `https://<ctx.hostname>` | always |
| `[server].trusted_proxies` | the `lb` subnet CIDR (uncommented) | `haproxy-pair` / `managed-l7`; on `caddy-on-box` the compose network's range |
| `[log].url` | `nats://<ip>:4222[,nats://<ip>:4222,...]` (this node's own NATS first, then `ctx.nats_peers`) | `nats-*` |
| `[log].ca_file` / `cert_file` / `key_file` | `/etc/observer-org/nats-tls/{ca.crt,node.crt,node.key}` (uncommented) | `nats-*` |
| `[metrics].listen` | `":<port of ctx.metrics_listen>"` (D19; compose publishes ctx.metrics_listen via OBSERVER_METRICS_BIND) | `ctx.metrics_listen` non-empty; the patcher tolerates an absent `[metrics]` section (a pre-D17 bundle) with a log line, never an assert |

### Azure provision names (the catalog's `provision` field; A3 adds them to `size_map.skus[]`)

| Price row id | provision |
|---|---|
| `azure.vm.b2ms` | `Standard_B2ms` |
| `azure.vm.d4as_v5` | `Standard_D4as_v5` |
| `azure.vm.e4as_v5` | `Standard_E4as_v5` |
| `azure.vm.d8as_v5` | `Standard_D8as_v5` |
| `azure.vm.d16as_v5` | `Standard_D16as_v5` |
| `azure.pg.burstable.b2ms` | `B_Standard_B2ms` |
| `azure.pg.gp.d4ds_v5` | `GP_Standard_D4ds_v5` |
| `azure.pg.mo.e4ds_v5` | `MO_Standard_E4ds_v5` |
| `azure.pg.gp.d8ds_v5` | `GP_Standard_D8ds_v5` |
| `azure.pg.mo.e8ds_v5` | `MO_Standard_E8ds_v5` |
| `azure.pg.gp.d16ds_v5` | `GP_Standard_D16ds_v5` |
| `azure.pg.mo.e16ds_v5` | `MO_Standard_E16ds_v5` |
| `azure.pg.mo.e32ds_v5` | `MO_Standard_E32ds_v5` |
| `azure.disk.premium.p10` | `Premium_LRS:128` |
| `azure.disk.premium.p15` | `Premium_LRS:256` |
| `azure.disk.premium.p20` | `Premium_LRS:512` |
| `azure.disk.premium.p30` | `Premium_LRS:1024` |
| `azure.disk.premium_v2.gib` | `PremiumV2_LRS` |

A disk provision name is `<sku>:<size_gib>`; the planner splits it into `app_disk_sku` +
`app_disk_gb` (the size is ALSO a Sizing key; the two must agree and the render test asserts it).

## AWS (C1b-aws, C3-aws, C8-aws, C10 - the Phase 3 contracts, plan section 5)

C7 (the `observer-postgres` image), C7b (the org listener behind an L7) and C9 (the first-boot
config patch) are unchanged in shape on AWS: the same image, the same `:8443` plain-HTTP
listener behind the NLB-fronted HAProxy pair or the ALB, and the same `observer-first-boot.sh`
8-step sequence and config rewrites (promoted to `_shared/cloudinit/files/`, P3-D1).

### C1b-aws data -> app outputs (read through `terraform_remote_state`)

| Output | Type | Meaning |
|---|---|---|
| `vpc_id` | string | the deployment's VPC |
| `subnet_ids` | map(list(string)) | `public`, `app`, `db` subnet ids, one per AZ (index `i % 3`, P3-D9) |
| `subnet_cidrs` | map(list(string)) | the same subnets' CIDRs (for `trusted_proxies` / security-group rules) |
| `bucket_name` | string | the ONE SoR bucket `<name_prefix>-sor` (P3-D4: versioning on, SSE-S3, public access blocked, TLS-only bucket policy; the org server writes its SoR keys at the bucket ROOT - it has no object-key-prefix capability - so `bundle/` and `pg-backup/` are only the bundle's and pgBackRest's own prefixes; `observer-archive/` is RESERVED, unused until the server gains a key-prefix knob; amended 2026-09-20, A+B review R-04) |
| `bundle_prefix` | string | `s3://<bucket>/bundle/` - the bundle files AND every `_shared/cloudinit/files/*` + AWS-variant script the first boot fetches (P3-D5) |
| `secrets_prefix_arn` | string | the Secrets Manager ARN pattern `observer-org/<name_prefix>/*` each instance profile may `secretsmanager:GetSecretValue` on (P3-D3) |
| `secret_names` | map(string) | logical -> Secrets Manager secret name (the SAME logical keys as Azure's C1b `secret_names`: `session-key`, `bearer-signing-key`, `policy-signing-key`, `scim-token`, `nats-password`, `pg-app-password`, `pg-control-dsn`, `pg-data-dsn`, `sealing-key`, `acr-pull-user`, `acr-pull-token`, `nats-ca`, `nats-cert-<i>`, `nats-key-<i>`, `pg-server-cert`, `pg-server-key`, `pg-ca`, `harness-gateway-token`, `saml-sp-cert`, `saml-sp-key`, `vm-ssh-key`; NO `object-sas` - S3 is reached by the instance role; absent keys = not minted for this answer set) |
| `sealing_key_secret_arn` | string | the `sealing-key` secret (`prevent_destroy`, `recovery_window_in_days = 30`), echoed by app |
| `pg_ca_secret_name` | string | Secrets Manager secret holding the CA the client verifies (`verify-full`): the RDS CA bundle `rds-ca-rsa2048-g1` (fetched by the module from the AWS-published PEM) on managed-*, the module-minted CA on self-hosted-separate |
| `postgres_endpoint` | string | host[:port] of the control/data database: the RDS address (never a guessed FQDN - D20's lesson), the PostgreSQL instance's private IP, or empty for `existing` |
| `app_data_volume_ids` | list(string) | one EBS volume per app node, attached by app-instance through a separate `aws_volume_attachment` so the instance is replaceable (P3-D6) |
| `app_nats_volume_ids` | list(string) | one per NATS-bearing app node on `nats-cluster`; `[]` otherwise |
| `nats_quorum_volume_id` | string | empty unless nats_nodes = 3 |
| `pg_data_volume_ids` | list(string) | the PostgreSQL EC2 data volume(s) on self-hosted-separate; `[]` otherwise |
| `app_private_ips` | list(string) | the PLANNED static private IP per app node - ONE derivation, in data, as on Azure |
| `nats_disk_gb` | number | D31 twin: the per-node NATS volume size in GiB; the app layer renders it as JetStream `max_file_store` (ctx `nats_max_file_store`) and refuses a larger `nats_max_bytes_gb` at plan time |
| `azs` | list(string) | the region's first three availability zones (`data.aws_availability_zones`); a plan-time precondition refuses a region with fewer (P3-D9) |

### C3-aws user-data contract (A2 owns the stubs; A1/B1 call `templatefile`)

Every `deploy/modules/_shared/aws/cloudinit/<role>.userdata.tftpl` takes ONE object `ctx`. The
user-data stub is the ONLY thing in `user_data` (AWS caps it at 16 KB, P3-D5): ~2 KB that
installs the `aws` CLI v2 (Ubuntu 24.04 apt) + docker, fetches `bundle_s3_uri` INCLUDING the
on-box scripts and units, `chmod`s them and execs `bootstrap-<role>.sh`; everything else is
fetched, nothing is inlined, so there is no `check-sync.sh` for AWS.

```hcl
ctx = {
  role                 = "app" | "pg" | "nats-quorum" | "haproxy"
  hostname             = string          # public hostname (app, haproxy)
  bundle_s3_uri        = string          # s3://<bucket>/bundle/ (C1b-aws bundle_prefix)
  secrets_prefix       = string          # observer-org/<name_prefix>/ (Secrets Manager name prefix, P3-D3)
  secret_names         = map(string)     # C1b-aws's map
  region               = string          # the AWS region (C1 location)
  image_tag            = string
  registry             = string
  postgres_mode        = "colocated" | "separate" | "managed" | "existing"
  log_mode             = "embedded" | "nats-single" | "nats-cluster"
  nats_peers           = list(string)    # private IPs of the other NATS nodes (routes)
  node_index           = number          # 0-based within the role
  acme                 = "http01" | "dns01" | "off"
  acme_staging         = bool
  app_disk_volume_id   = string          # the EBS volume id; resolved on the box as /dev/disk/by-id/nvme-Amazon_Elastic_Block_Store_vol<id> (P3-D13: Nitro exposes volumes as NVMe, /dev/sdf names are advisory; 600 s budget, progress lines - the D8/D29 lesson), mounted at /var/lib/observer-docker
  nats_disk_volume_id  = string          # "" on non-nats roles; else the NATS volume, mounted at /var/lib/observer-nats (jetstream/ = the nats service's /data bind, CD-1)
  pg_disk_volume_id    = string          # pg role only
  nats_max_file_store  = string          # D31: "<nats_disk_gb>GB" = the brokers' JetStream max_file_store; "" when embedded
  metrics_listen       = string          # "" = off, else "<private-ip>:9464" (D19)
  harness_runners      = number
  l7                   = "caddy-on-box" | "haproxy-pair" | "managed-l7"
  backend_ips          = list(string)    # haproxy role: the app nodes' private IPs (= C1b-aws app_private_ips); [] on other roles
  object_bucket        = string          # C8-aws: OBSERVER_OBJECT_BUCKET ("" when object_store = local-disk)
  object_region        = string          # C8-aws: OBSERVER_OBJECT_REGION
  trusted_proxy_cidr   = string          # C9: the CIDR written into [server].trusted_proxies ("" = leave commented; the ALB subnets' CIDRs on managed-l7, P3-D8)
}
```

`tls_certificate_secret_arn` (the customer PFX in Secrets Manager, `haproxy-pair`) reaches the
box through `secret_names`, never as a ctx literal; `tls_certificate_arn` (ACM, `managed-l7`)
never reaches a box at all - the ALB terminates with it.

### C8-aws what `observer-env-sync.sh` (AWS variant, same interface) fills

C8's `.env` source column for AWS: `OBSERVER_OBJECT_BACKEND=s3`, `_ENDPOINT=https://s3.<region>.amazonaws.com`,
`_BUCKET`, `_REGION`, no keys; `NATS_PASSWORD` / `POSTGRES_PASSWORD` / `HARNESS_GATEWAY_TOKEN`
from Secrets Manager by env-sync; the registry login = the stored ACR token (K3) OR, when
`registry` matches `*.dkr.ecr.<region>.amazonaws.com`, `aws ecr get-login-password` under the
instance role (a capability resolved at the boundary from the registry host's shape, never a
cloud branch). The fetch runs through the instance role via the `aws` CLI v2 (P3-D3: no
long-lived credential anywhere on the box; the ONLY reader of Secrets Manager on a box is
`observer-env-sync.sh`). Row by row, against the Azure C8 table:

| `.env` key or file | Source | Notes |
|---|---|---|
| `OBSERVER_CONTROL_STORE_DSN`, `OBSERVER_DATA_STORE_DSN` | Secrets Manager `pg-control-dsn`, `pg-data-dsn` | data layer composes them (`sslmode=verify-full&sslrootcert=/etc/observer-org/pg-tls/ca.crt`; the RDS CA bundle `rds-ca-rsa2048-g1` as `pg-ca` on managed-*) |
| `OBSERVER_LOG_PASSWORD`, `NATS_PASSWORD` | Secrets Manager `nats-password` | the two are one secret |
| `OBSERVER_OBJECT_BACKEND`, `OBSERVER_OBJECT_ENDPOINT`, `OBSERVER_OBJECT_BUCKET`, `OBSERVER_OBJECT_REGION` | ctx (non-secret): `s3`, `https://s3.<region>.amazonaws.com`, `<bucket>`, `<region>` | `object_store = cloud-bucket` only; NO access key - the default chain resolves the instance role (P3-D4); no `OBSERVER_OBJECT_ACCOUNT_SAS` row exists on AWS |
| `OBSERVER_ORG_SECRET_KEY` | Secrets Manager `sealing-key` | the env rail, as on Azure |
| `OBSERVER_PG_APP_PASSWORD` (the plan's `POSTGRES_PASSWORD`) | Secrets Manager `pg-app-password` | compact (colocated) only |
| `OBSERVER_ORG_IMAGE`, `OBSERVER_POSTGRES_IMAGE`, `HARNESS_GATEWAY_IMAGE` | rendered by the planner (registry + tag) | never CHANGEME on the module path |
| `GATEWAY_TOKEN` (the plan's `HARNESS_GATEWAY_TOKEN`) | Secrets Manager `harness-gateway-token` | `harness = on` only |
| `secrets/session.key`, `secrets/bearer/signing.key`, `secrets/policy/signing.key`, `secrets/scim/token` | Secrets Manager `session-key`, `bearer-signing-key`, `policy-signing-key`, `scim-token` | 0600, uid 65532; `policy/signing.key` as on Azure (the org's POLICY signing key, `[policy].signing_key_path`) |
| `secrets/saml/sp.crt`, `secrets/saml/sp.key` | Secrets Manager `saml-sp-cert`, `saml-sp-key` | `identity = saml` only |
| `secrets/pg-tls/{server.crt,server.key,ca.crt}` | Secrets Manager `pg-server-cert`, `pg-server-key`, `pg-ca` | self-hosted only; key owner uid 999 |
| `secrets/nats-tls/{ca.crt,node.crt,node.key}` | Secrets Manager `nats-ca`, `nats-cert-<i>`, `nats-key-<i>` | `nats-*` log only |
| `secrets/pgbackrest.conf` | template in `_shared/aws/cloudinit/files/pgbackrest.conf.tftpl` (C10) | self-hosted only; no key material in it (`repo1-s3-key-type=auto`) |
| docker login | Secrets Manager `acr-pull-user`, `acr-pull-token` (K3), or `aws ecr get-login-password` when the registry host is `*.dkr.ecr.<region>.amazonaws.com` | never written to disk beyond docker's own config |

The `.env` upload precondition, the atomic writes and the version-gated restart are unchanged
from C8.

### C10 pgBackRest on AWS

`repo1-type=s3`, `repo1-s3-bucket=<bucket>`, `repo1-s3-region=<region>`,
`repo1-s3-endpoint=s3.<region>.amazonaws.com`, `repo1-s3-key-type=auto` (the instance role - no
SAS, no rotation, `sasExpiryWarning` inapplicable, DR-11 executed natively), `repo1-path=/pg-backup`;
`repo1-retention-full=5`, `repo1-retention-diff=35`, `process-max=2` as in C7. The sealing-key copy
beside each backup (`observer-copy-sealing-key.sh`, AWS variant) is `aws s3 cp` with the instance
role. The timers, `restore-drill.sh` and the D13 `-u postgres` exec rule are the promoted
`_shared/cloudinit/files/*` units, unchanged.

### AWS provision names (bound by the catalog in A3; the plan's names)

| provision | vCPU / GiB | Price row id |
|---|---|---|
| `m6a.xlarge` | 4 / 16 | bound by the catalog in A3 |
| `m6a.2xlarge` | 8 / 32 | bound by the catalog in A3 |
| `m6a.4xlarge` | 16 / 64 | bound by the catalog in A3 |
| `r6a.xlarge` | 4 / 32 (memory-optimised, the PostgreSQL EC2) | bound by the catalog in A3 |
| `t3.large` | 2 / 8 (quorum, HAProxy) | bound by the catalog in A3 |
| `db.t4g.large` | 2 / 8 | bound by the catalog in A3 |
| `db.m6g.xlarge` | 4 / 16 | bound by the catalog in A3 |
| `db.m6g.2xlarge` | 8 / 32 | bound by the catalog in A3 |
| `db.r6g.xlarge` | 4 / 32 | bound by the catalog in A3 |
| `db.r6g.2xlarge` | 8 / 64 | bound by the catalog in A3 |
| `db.r6g.8xlarge` | 32 / 256 | bound by the catalog in A3 |
| `gp3:<GiB>` | the EBS data volume | bound by the catalog in A3 |

A volume provision name is `<type>:<size_gib>`; the planner splits it into `app_disk_type` +
`app_disk_gb` exactly as Azure's `<sku>:<size_gib>` splits into `app_disk_sku` + `app_disk_gb`
(the size is ALSO a Sizing key; the two must agree and the render test asserts it). RDS
Multi-AZ prices at 2x the class (the snapshot's rule).

## Fixtures (P2-D15, P3-D14)

`deploy/modules/<shape>/<cloud>/<layer>/tests/fixtures/<answer-set-id>.tfvars` are the
planner's rendered tfvars for RA-0, RA-1a, RA-1b (compact) and RA-2, RA-2-selfhosted, RA-3,
RA-3-selfhosted (appliance), per cloud. A1/B1 hand-write them first from this table; A3's
`render/tfvars_test.go` renders the same sets and asserts byte equality (drift both ways
fails). `tofu test` runs read them with `-var-file` (Azure: `mock_provider "azurerm"`; AWS:
`mock_provider "aws"`).
"""

if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
