#!/usr/bin/env python3
"""Generate the Phase 2 contract stubs: deploy/modules/CONTRACT.md and, per
root module, variables.tf / versions.tf / backend.tf, from ONE variable table
(plan P2 contract C1). Re-run after editing the table; never hand-edit the
generated variables.tf (the header says so)."""
import os, sys, textwrap

ROOT = "deploy/modules"
SHAPES = ["compact", "appliance"]
LAYERS = ["bootstrap", "data", "app"]

# (name, type, default, layers, shapes, description, validation)
# default None = required. shapes None = both. validation = (condition, message) or None.
NOT_CHANGEME = lambda v: (f'!startswith(lower(var.{v}), "changeme")', f'{v} is still the CHANGEME placeholder; edit terraform/*.tfvars')
V = [
 # ---- identity (all layers) ----
 ("name_prefix", "string", None, LAYERS, None,
  "3-12 lowercase alphanumerics prefixed to every resource name (also the state storage account name, so it must be globally unique-ish).",
  ('can(regex("^[a-z0-9]{3,12}$", var.name_prefix)) && var.name_prefix != "changeme"', "name_prefix must match ^[a-z0-9]{3,12}$ and not be the CHANGEME placeholder")),
 ("location", "string", None, LAYERS, None,
  "Azure region (e.g. eastus2). RA-3 (app_layout = ha) needs a region with three availability zones.", NOT_CHANGEME("location")),
 ("answer_set_id", "string", None, LAYERS, None,
  "The catalog answer set this deployment was rendered from (RA-1a, RA-2, ...). Informational: tagged on every resource, never used to derive a size.", None),
 ("tags", "map(string)", "{}", LAYERS, None, "Extra tags merged onto every resource.", None),
 # ---- bootstrap ----
 ("state_container_name", "string", '"tfstate"', ["bootstrap"], None, "Blob container (in the bootstrap-made storage account) that holds the data and app layer states.", None),
 # ---- data (+ app reads some of these too) ----
 ("admin_object_id", "string", None, ["data"], None,
  "Entra object id (user or group) granted Key Vault Secrets Officer, so an operator can read/rotate secrets. Never a service principal SuperBased holds.",
  ('can(regex("^[0-9a-fA-F-]{36}$", var.admin_object_id))', "admin_object_id must be a GUID")),
 ("operator_cidr", "list(string)", "[]", ["data"], None,
  "Public CIDRs of the machines that run tofu apply (the app layer uploads the bundle blobs from there); added to the SoR storage account firewall beside the VNet subnets. [] = only the VNet can reach the account, and the bundle upload must run from inside it.", None),
 ("ssh_public_key", "string", '""', ["data"], None,
  "OpenSSH public key for the VMs' admin user; empty = the data layer generates an ed25519 keypair and stores the PRIVATE key in Key Vault as vm-ssh-key (the public key is a data-layer output the app layer reads).", None),
 ("object_store", "string", None, ["data", "app"], None, "Catalog axis object_store: local-disk (compact only) | cloud-bucket.",
  ('contains(["local-disk", "cloud-bucket"], var.object_store)', "object_store must be local-disk or cloud-bucket")),
 ("storage_replication", "string", '"LRS"', ["data"], None, "Storage account replication for the SoR account: LRS (single-zone sets) | ZRS (HA sets).",
  ('contains(["LRS", "ZRS"], var.storage_replication)', "storage_replication must be LRS or ZRS")),
 ("app_nodes", "number", None, ["data", "app"], None, "Number of --role all app VMs (Sizing app_nodes): 1 (single) or 2 (ha). One data disk is created per app node.",
  ("var.app_nodes >= 1 && var.app_nodes <= 2", "app_nodes must be 1 or 2 in Phase 2")),
 ("app_disk_gb", "number", None, ["data"], None, "Per app node premium data disk size in GiB (Sizing app_disk_gb): holds /var/lib/observer-org, the docker volumes and, on compact, the PostgreSQL data.", None),
 ("app_disk_sku", "string", '"Premium_LRS"', ["data"], None, "Managed disk SKU for the app data disks (the catalog binds P10/P15/P20/P30 by size; Premium_LRS tiers by size).", None),
 ("nats_nodes", "number", "0", ["data", "app"], None, "NATS processes (Sizing nats_nodes): 0 embedded, 1 single, 3 cluster (two on the app nodes + one quorum VM).",
  ("contains([0, 1, 3], var.nats_nodes)", "nats_nodes must be 0, 1 or 3")),
 ("nats_disk_gb", "number", "0", ["data"], None, "Per NATS node premium disk in GiB (Sizing nats_disk_gb); 0 when the log is embedded (it then lives on the app data disk).", None),
 ("log", "string", None, ["data", "app"], None, "Catalog axis log: embedded | nats-single | nats-cluster.",
  ('contains(["embedded", "nats-single", "nats-cluster"], var.log)', "log must be embedded, nats-single or nats-cluster")),
 ("harness", "string", '"off"', ["data", "app"], None, "Catalog axis harness: off | on (harness-gateway runner containers; the data layer mints GATEWAY_TOKEN when on).",
  ('contains(["off", "on"], var.harness)', "harness must be off or on")),
 ("identity", "string", '"oidc"', ["data", "app"], None, "Catalog axis identity: oidc | saml | local (the data layer mints the SAML SP keypair when saml).",
  ('contains(["oidc", "saml", "local"], var.identity)', "identity must be oidc, saml or local")),
 ("tls_certificate_secret_id", "string", '""', ["app"], None, "Key Vault secret/certificate id of a customer-provided PFX for the public hostname; empty = ACME per var.acme.", None),
 # ---- appliance data ----
 ("postgres", "string", None, ["data", "app"], ["appliance"], "Catalog axis postgres: managed-single | managed-ha | self-hosted-separate | existing.",
  ('contains(["managed-single", "managed-ha", "self-hosted-separate", "existing"], var.postgres)', "postgres must be managed-single, managed-ha, self-hosted-separate or existing")),
 ("pg_sku", "string", '""', ["data"], ["appliance"], "Flexible Server sku_name (catalog provision name, e.g. MO_Standard_E4ds_v5) for managed-*; empty otherwise.", None),
 ("pg_vm_size", "string", '""', ["data"], ["appliance"], "VM size (catalog provision name, e.g. Standard_E4as_v5) for self-hosted-separate; empty otherwise.", None),
 ("pg_instances", "number", "1", ["data"], ["appliance"], "Sizing pg_instances: 1, or 2 = a streaming replica VM (self-hosted) / ZoneRedundant HA (managed-ha).",
  ("contains([1, 2], var.pg_instances)", "pg_instances must be 1 or 2")),
 ("pg_disk_gb", "number", "0", ["data"], ["appliance"], "PostgreSQL provisioned storage in GiB (Sizing pg_disk_gb): Flexible Server storage_mb, or the PostgreSQL VM data disk.", None),
 ("pg_backup_retention_days", "number", "35", ["data"], ["appliance"], "Flexible Server backup retention (plan 4.4: 35 days of PITR); the self-hosted job uses the same number.",
  ("var.pg_backup_retention_days >= 7 && var.pg_backup_retention_days <= 35", "pg_backup_retention_days must be 7..35")),
 ("app_layout", "string", '"single"', ["data", "app"], ["appliance"], "Catalog axis app_layout: single (RA-2) | ha (RA-3).",
  ('contains(["single", "ha"], var.app_layout)', "app_layout must be single or ha")),
 # ---- app ----
 ("hostname", "string", None, ["app"], None, "Public HTTPS hostname of the dashboard (external_url = https://<hostname>).",
  ('can(regex("^[a-z0-9.-]+\\\\.[a-z]{2,}$", lower(var.hostname))) && !startswith(lower(var.hostname), "changeme")', "hostname must be a DNS name and not the CHANGEME placeholder")),
 ("dns_zone_name", "string", '""', ["app"], None, "Existing Azure DNS zone to create the A record in (data source, never created); empty = no record, the public IP is an output.", None),
 ("dns_zone_resource_group", "string", '""', ["app"], None, "Resource group of dns_zone_name.", None),
 ("admin_cidr", "list(string)", None, ["app"], None, "Source CIDRs allowed to SSH (port 22) to the VMs; [] = no SSH rule at all (Bastion or serial console are the customer's choice).", None),
 ("monitoring_cidr", "list(string)", "[]", ["app"], None, "Source CIDRs allowed to scrape /metrics (:9464); [] = the metrics listener is not opened.", None),
 ("l7", "string", None, ["app"], None, "Catalog axis l7: caddy-on-box (single node) | haproxy-pair | managed-l7.",
  ('contains(["caddy-on-box", "haproxy-pair", "managed-l7"], var.l7)', "l7 must be caddy-on-box, haproxy-pair or managed-l7")),
 ("acme", "string", '"http01"', ["app"], None, "Certificate issuance when tls_certificate_secret_id is empty: http01 (Caddy, single node) | dns01 (certbot via the VM identity on the HAProxy pair) | off.",
  ('contains(["http01", "dns01", "off"], var.acme)', "acme must be http01, dns01 or off")),
 ("acme_staging", "bool", "false", ["app"], None, "Use the Let's Encrypt staging directory (test runs; avoids rate limits).", None),
 ("app_vm_size", "string", None, ["app"], None, "App VM size (catalog provision name, e.g. Standard_D4as_v5).", NOT_CHANGEME("app_vm_size")),
 ("nats_replicas", "number", "1", ["app"], None, "[log].replicas rendered into config (Sizing nats_replicas).", ("var.nats_replicas >= 1 && var.nats_replicas <= 5", "nats_replicas must be 1..5")),
 ("nats_max_age_hours", "number", "24", ["app"], None, "[log].max_age_hours (Sizing nats_max_age_hours).", None),
 ("nats_max_bytes_gb", "number", "10", ["app"], None, "[log].max_bytes_gb (Sizing nats_max_bytes_gb).", None),
 ("lb_nodes", "number", "0", ["app"], ["appliance"], "HAProxy VMs (Sizing lb_nodes): 2 for haproxy-pair, else 0.", ("contains([0, 2], var.lb_nodes)", "lb_nodes must be 0 or 2")),
 ("small_vm_size", "string", '"Standard_B2ms"', ["app"], None, "VM size for the quorum and HAProxy VMs; override in regions where B2ms is capacity-restricted.", None),
 ("harness_runners", "number", "0", ["app"], None, "harness-gateway runner containers on the app nodes (Sizing harness_runners).", None),
 ("retention_days", "number", "365", ["app"], None, "[server].data_retention_days (catalog axis retention).", ("contains([90, 180, 365, 730], var.retention_days)", "retention_days must be 90, 180, 365 or 730")),
 ("image_tag", "string", None, ["app"], None, "Release tag of observer-org / observer-postgres / harness-gateway (stamped by the planner from the binary's own version).", NOT_CHANGEME("image_tag")),
 ("registry", "string", None, ["app"], None, "Image registry host: superbasedenterprise.azurecr.io (vendor-private) or the customer mirror.", NOT_CHANGEME("registry")),
 ("bundle_dir", "string", '"."', ["app"], None, "Local path of the rendered bundle directory (config.production.toml, docker-compose*.yaml, nats.conf, ...) the app layer uploads to the private bundle container.", None),
 ("data_state", "object({ storage_account_name = string, container_name = string, key = string })", None, ["app"], None,
  "Where the data layer's state lives (rendered into terraform/app.tfvars from bootstrap's outputs); read with terraform_remote_state.", None),
]

def applies(v, layer, shape):
    _, _, _, layers, shapes, _, _ = v
    return layer in layers and (shapes is None or shape in shapes)

def render_variables(layer, shape):
    out = [f"""# GENERATED by scripts (deploy/modules/CONTRACT.md is the source of truth for
# this table; the Go test render/tfvars_test.go reads THIS file to learn which
# variables the layer declares). Add a variable to CONTRACT.md's table and
# regenerate; do not hand-edit. Phase 2 plan contract C1.
#
# Root: deploy/modules/{shape}/azure/{layer}
"""]
    for v in V:
        if not applies(v, layer, shape):
            continue
        name, typ, default, _, _, desc, val = v
        out.append(f'variable "{name}" {{')
        out.append(f'  type        = {typ}')
        if default is not None:
            out.append(f'  default     = {default}')
        out.append('  description = ' + hcl_string(desc))
        if val:
            cond, msg = val
            out.append('  validation {')
            out.append(f'    condition     = {cond}')
            out.append('    error_message = ' + hcl_string(msg))
            out.append('  }')
        out.append('}\n')
    return "\n".join(out)

def hcl_string(s):
    return '"' + s.replace('\\', '\\\\').replace('"', '\\"') + '"'

VERSIONS = """# Provider pins shared by every Phase 2 root (plan contract C1; DR-15: valid
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
"""

BACKEND = """# Partial backend configuration (plan P2-D10): the storage account, container
# and key arrive from terraform/backend-<layer>.hcl, rendered by the planner
# from the bootstrap layer's outputs:
#   tofu init -backend-config=../../../../terraform/backend-%s.hcl
# use_azuread_auth = true so no storage key is needed on the operator's machine.
terraform {
  backend "azurerm" {
    use_azuread_auth = true
  }
}
"""

def main():
    os.makedirs(ROOT, exist_ok=True)
    for shape in SHAPES:
        for layer in LAYERS:
            d = os.path.join(ROOT, shape, "azure", layer)
            os.makedirs(d, exist_ok=True)
            with open(os.path.join(d, "variables.tf"), "w") as f:
                f.write(render_variables(layer, shape))
            with open(os.path.join(d, "versions.tf"), "w") as f:
                f.write(VERSIONS)
            if layer != "bootstrap":
                with open(os.path.join(d, "backend.tf"), "w") as f:
                    f.write(BACKEND % layer)
    # CONTRACT.md table
    rows = ["| Variable | Type | Default | Layers | Shapes | Description |", "|---|---|---|---|---|---|"]
    for name, typ, default, layers, shapes, desc, val in V:
        rows.append(f"| `{name}` | `{typ}` | {'required' if default is None else '`'+default+'`'} | {', '.join(layers)} | {'both' if shapes is None else ', '.join(shapes)} | {desc}{' Validated.' if val else ''} |")
    table = "\n".join(rows)
    with open(os.path.join(ROOT, "CONTRACT.md"), "w") as f:
        f.write(CONTRACT.replace("@@TABLE@@", table))
    print("generated", ROOT)

CONTRACT = """# Phase 2 module contracts (the stub every wave-A/B agent codes against)

Plan of record: `docs/plans/enterprise-deployment-phase-2-implementation-plan-2026-09-18.md`
(section 5, contracts C1-C6; every decision P2-D1..P2-D18 RULED 2026-09-18). This file is
the rendered form of the variable table that lives in `scripts/gen-module-stubs.py`, which
regenerates every root's `variables.tf`, `versions.tf`, `backend.tf` AND this file. Edit the
script's table, re-run it, commit both. A variable that is not in this table does not exist.

## Layout (P2-D1, P2-D10)

```
deploy/modules/
  CONTRACT.md                      this file
  README.md                        operator-facing: what the roots are, apply order, teardown
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
     cloudinit/    *.yaml.tftpl templates + files/ (units, scripts) - owned by A2, see C3
  compact/azure/{bootstrap,data,app}/     roots for RA-0 / RA-1a / RA-1b
  appliance/azure/{bootstrap,data,app}/   roots for RA-2 (single) / RA-3 (ha)
```

**Layer homes (refined during wave A, a contract deviation from P2-D10's parenthetical):**
the VNet, subnets and private DNS zone live in the **data** layer, not app - a Flexible
Server with private access requires its delegated subnet at creation, and a VNet is a pet
(replacing it destroys everything attached). NSGs, NICs, public IPs, VMs, LBs, App Gateway,
DNS records and backup policies are the app layer's. The PostgreSQL VM (self-hosted-separate)
lives WHOLE in the data layer (its data disk is the pet; `tofu apply -replace` rebuilds the VM).

## C1 root-module variables

@@TABLE@@

Rules: no `developers` variable anywhere; every quantity above is copied from
`AnswerSet.Sizing` by the planner (`render.Files` -> `terraform/<layer>.tfvars`), every SKU
name from the catalog's `provision` field; `validation` blocks refuse `CHANGEME`; no variable
is `sensitive` because no secret is ever a variable.

## C1b data -> app outputs (read through `terraform_remote_state`)

| Output | Type | Meaning |
|---|---|---|
| `resource_group_name` | string | the deployment's resource group (created by bootstrap, echoed) |
| `vnet_id`, `subnet_ids` | string, map(string) | `app`, `data`, `lb` subnet ids |
| `key_vault_id`, `key_vault_uri` | string | the vault the VMs read |
| `secret_names` | map(string) | logical -> Key Vault secret name: `session-key`, `bearer-signing-key`, `scim-token`, `nats-password`, `pg-app-password`, `pg-control-dsn`, `pg-data-dsn`, `sealing-key`, `object-sas`, `acr-pull-user`, `acr-pull-token`, `nats-ca`, `nats-cert-<i>`, `nats-key-<i>`, `pg-server-cert`, `pg-server-key`, `pg-ca`, `harness-gateway-token`, `saml-sp-cert`, `saml-sp-key` (absent keys = not minted for this answer set) |
| `sealing_key_secret_id` | string | the plan's output, echoed by app |
| `vm_ssh_public_key` | string | the admin user's public key (customer-provided or generated) |
| `storage_account_name`, `archive_container_name`, `bundle_container_name`, `bundle_container_url` | string | the SoR account and the two containers |
| `object_sas_expires_at` | string (RFC 3339) | when the minted SAS expires |
| `app_data_disk_ids` | list(string) | one per app node, attached by app-vm at LUN 0 |
| `nats_quorum_disk_id` | string | empty unless nats_nodes = 3 |
| `postgres_endpoint` | string | host[:port] of the control/data database (managed FQDN, the PG VM's private IP, or empty for `existing`) |
| `postgres_ca_secret_name` | string | Key Vault secret holding the CA the client verifies (`verify-full`) |
| `app_private_ips` | list(string) | the PLANNED static private IP per app node (`cidrhost(app subnet, 10 + index)`); the app layer assigns exactly these to the NICs and the data layer puts them in the NATS cert SANs - ONE derivation, in data (wave-A fold of A1's open question 1) |
| `app_subnet_prefix` | string | the app subnet CIDR (for trusted_proxies / NSG rules) |
| `nats_urls` | list(string) | rendered by app once the VMs' private IPs are known; data outputs the planned private IPs for the static-IP NICs |

## C3 cloud-init contract (A2 owns the templates; A1/B1 call `templatefile`)

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
  metrics_listen       = string          # "" = off, else "<private-ip>:9464"
  app_disk_lun         = number          # data disk LUN (mounted at /var/lib/observer-org)
  pg_disk_lun          = number          # pg role only
  nats_disk_lun        = number          # -1 when the log store lives on the app disk
  harness_runners      = number
  l7                   = "caddy-on-box" | "haproxy-pair" | "managed-l7"
  tls_certificate_secret_id = string  # "" = ACME per acme; else the Key Vault secret holding a customer PFX (P2-D5)
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

## C7 `observer-postgres` image contract (A2 builds it; A3's compose override runs it)

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

## C8 what `observer-env-sync.sh` fills (A2 writes the script; A3 renders the placeholders)

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
| `secrets/session.key`, `secrets/bearer/signing.key`, `secrets/scim/token` | Key Vault `session-key`, `bearer-signing-key`, `scim-token` | 0600, uid 65532 |
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

## C9 first-boot config patch (A2's `observer-first-boot.service`; A3 keeps the keys present)

The planner renders `config.production.toml` before the infrastructure exists, so first boot
rewrites EXACTLY these keys from `ctx`, each with a `grep` assert after the edit (a miss is a
hard failure, never a silent skip):

| Key | Value | When |
|---|---|---|
| `[server].external_url` | `https://<ctx.hostname>` | always |
| `[server].trusted_proxies` | the `lb` subnet CIDR (uncommented) | `haproxy-pair` / `managed-l7`; on `caddy-on-box` the compose network's range |
| `[log].url` | `nats://<ip>:4222[,nats://<ip>:4222,...]` (this node's own NATS first, then `ctx.nats_peers`) | `nats-*` |
| `[log].ca_file` / `cert_file` / `key_file` | `/etc/observer-org/nats-tls/{ca.crt,node.crt,node.key}` (uncommented) | `nats-*` |
| `[metrics].listen` | `ctx.metrics_listen` | wave B (the key does not exist yet; the patcher must tolerate its absence until then) |

## Azure provision names (the catalog's `provision` field; A3 adds them to `size_map.skus[]`)

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

## Fixtures (P2-D15)

`deploy/modules/<shape>/azure/<layer>/tests/fixtures/<answer-set-id>.tfvars` are the
planner's rendered tfvars for RA-0, RA-1a, RA-1b (compact) and RA-2, RA-2-selfhosted, RA-3,
RA-3-selfhosted (appliance). A1/B1 hand-write them first from this table; A3's
`render/tfvars_test.go` renders the same sets and asserts byte equality (drift both ways
fails). `tofu test` runs read them with `-var-file`.
"""

if __name__ == "__main__":
    main()
