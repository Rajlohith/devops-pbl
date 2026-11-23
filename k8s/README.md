# NetScope Kubernetes Deployment

These manifests deploy NetScope to a Kubernetes cluster in the `netscope`
namespace. The application image must already be available to the cluster
as `netscope:local`.

This deployment was verified on a single-node Minikube cluster (Docker driver). It starts with one replica of each component; the web Deployment is autoscaled by a HorizontalPodAutoscaler (see [step 11](#11-enable-autoscaling-hpa) and [Current scope](#current-scope)).

## Components

| Manifest | Resources | Purpose |
|---|---|---|
| `namespace.yaml` | Namespace `netscope` | Isolates all NetScope resources. |
| `configmap.yaml` | ConfigMap `netscope-config` | Non-sensitive application settings. |
| `storage.yaml` | PersistentVolumeClaim `uploads-pvc` | Uploaded capture files shared by web and worker. |
| `postgres.yaml` | Service + StatefulSet `postgres` | PostgreSQL 16 with its own persistent volume. |
| `valkey.yaml` | Service + Deployment `valkey` | Valkey 8 broker for Celery (no persistent volume). |
| `migration.yaml` | Job `netscope-migration` | Applies database migrations once. |
| `web.yaml` | Service + Deployment `netscope-web` | Flask application served by Gunicorn on port 8000. |
| `worker.yaml` | Deployment `netscope-worker` | Celery worker that analyses uploaded captures. |
| `hpa.yaml` | HorizontalPodAutoscaler `netscope-web-hpa` | Scales `netscope-web` between 1 and 5 replicas on CPU utilisation. |

The `netscope-secrets` Secret is **not** stored in the repository; you create it in step 2.

Services reach each other through Kubernetes DNS names: `postgres:5432` and `valkey:6379`.

## Prerequisites

- A running Kubernetes cluster and `kubectl` configured for it (verify with `kubectl get nodes`).
- The `netscope:local` image built with `docker build -t netscope:local .` (see the Docker Deployment section of the root `README.md`).
- For Minikube, load the image into the cluster; no registry push is needed because the manifests use `imagePullPolicy: IfNotPresent`:

```bash
minikube image load netscope:local
```

- A `standard` StorageClass (Minikube provides one). The PVCs in `storage.yaml` and `postgres.yaml` request it by name.
- Metrics Server running in the cluster (needed only for step 11; verify with `kubectl top nodes`).
- Optional: `openssl` for generating secrets and `jq` for the verification script.

Run all commands from the repository root.

## 1. Create the namespace

```bash
kubectl apply -f k8s/namespace.yaml
```

## 2. Create the Secret

The manifests read two keys from a Secret named `netscope-secrets`: `POSTGRES_PASSWORD` and `NETSCOPE_SECRET_KEY`. Create it directly with `kubectl` so the values never enter version control:

```bash
kubectl create secret generic netscope-secrets \
  --namespace netscope \
  --from-literal=POSTGRES_PASSWORD="$(openssl rand -hex 24)" \
  --from-literal=NETSCOPE_SECRET_KEY="$(openssl rand -base64 48)"
```

Notes:

- Use a URL-safe password such as hex. The pods build the database URL as `postgresql+psycopg://netscope:$(POSTGRES_PASSWORD)@postgres:5432/netscope`, so characters such as `/`, `@`, `:` or `+` in the password would corrupt it.
- PostgreSQL applies `POSTGRES_PASSWORD` only when its data volume is first initialised. Changing the Secret later does not change the password inside an existing database.
- Never commit secret values or paste them into issues or logs. Anyone who knows `NETSCOPE_SECRET_KEY` can forge session cookies.
- Verify the keys exist without printing the values:

```bash
kubectl describe secret netscope-secrets -n netscope
```

## 3. Apply the ConfigMap

```bash
kubectl apply -f k8s/configmap.yaml
```

`netscope-config` provides these settings to the web, worker and migration pods:

| Key | Value | Meaning |
|---|---|---|
| `NETSCOPE_ENV` | `production` | Production configuration: a secret key is mandatory and the session cookie is marked `Secure`. |
| `NETSCOPE_UPLOAD_FOLDER` | `/data/uploads` | Where capture files are stored (the mount point of `uploads-pvc`). |
| `NETSCOPE_FRONTEND_DIST` | `/app/frontend/dist` | Compiled Vue app served by Flask. |
| `NETSCOPE_REDIS_URL` | `redis://valkey:6379/0` | Celery broker, addressed through the `valkey` Service. |
| `NETSCOPE_MAX_UPLOAD_BYTES` | `209715200` | Maximum upload size (200 MiB). |

`NETSCOPE_DATABASE_URL` is not in the ConfigMap because it contains the password. Each pod assembles it from `POSTGRES_PASSWORD`, which must therefore be defined earlier in the container's `env` list than the variable that references it. The manifests already do this.

See the root `README.md` for the full configuration reference.

## 4. Create persistent storage

```bash
kubectl apply -f k8s/storage.yaml
kubectl get pvc -n netscope
```

`uploads-pvc` requests 2 GiB with access mode `ReadWriteOnce` from the `standard` StorageClass. Both the web and worker pods mount it at `/data/uploads`, so a capture saved by the web pod can be read by the worker.

Depending on the StorageClass, a PVC may stay `Pending` until a pod first uses it; that is normal.

## 5. Deploy PostgreSQL

```bash
kubectl apply -f k8s/postgres.yaml
kubectl rollout status statefulset/postgres -n netscope
```

PostgreSQL 16 runs as a StatefulSet with one replica behind the `postgres` Service (port 5432). The database and user are both `netscope`; the password comes from the Secret. Data lives in a volume claim template that produces the PVC `postgres-data-postgres-0` (2 GiB, `ReadWriteOnce`) mounted at `/var/lib/postgresql/data`, with `PGDATA` set to a `pgdata` subdirectory. Readiness and liveness probes run `pg_isready`. Resources: requests 200m CPU and 256Mi memory, limits 1 CPU and 1Gi.

## 6. Deploy Valkey

```bash
kubectl apply -f k8s/valkey.yaml
kubectl rollout status deployment/valkey -n netscope
```

Valkey 8 runs as a single-replica Deployment behind the `valkey` Service (port 6379), with `valkey-cli ping` readiness and liveness probes. It has no persistent volume, so queued tasks do not survive a Valkey pod restart; capture status is stored in PostgreSQL, so a task lost with the pod can leave a capture in `pending`. The retry endpoint accepts only `uploaded` or `failed` captures, so such a capture has to be deleted and uploaded again.

## 7. Run database migrations

```bash
kubectl apply -f k8s/migration.yaml
kubectl wait --for=condition=complete job/netscope-migration -n netscope --timeout=180s
kubectl logs job/netscope-migration -n netscope
```

The Job runs `flask --app wsgi db upgrade` in the `netscope:local` image. An init container first waits until PostgreSQL accepts connections (`pg_isready`). The Job does not restart failed pods (`restartPolicy: Never`) and retries up to three times (`backoffLimit: 3`). Migrations run as a finite Job rather than at web startup, so that web replicas never race to alter the schema.

In the verified deployment the Job completed and applied all three migrations: users and captures; packets, flows and analysis results; and network intelligence.

A Job's pod template cannot be edited in place. To run migrations again (for example after deploying a newer image), delete the finished Job first:

```bash
kubectl delete job netscope-migration -n netscope
kubectl apply -f k8s/migration.yaml
```

## 8. Deploy the web application

```bash
kubectl apply -f k8s/web.yaml
kubectl rollout status deployment/netscope-web -n netscope
```

`netscope-web` runs `gunicorn --bind 0.0.0.0:8000 wsgi:app` and is exposed inside the cluster by a `ClusterIP` Service on port 8000.

| Aspect | Configuration |
|---|---|
| Replicas | 1 |
| Init containers | `wait-for-postgres` and `wait-for-valkey` block startup until both dependencies respond. |
| Configuration | All keys of `netscope-config`, plus `NETSCOPE_SECRET_KEY` and `POSTGRES_PASSWORD` from the Secret and the assembled `NETSCOPE_DATABASE_URL`. |
| Storage | `uploads-pvc` mounted at `/data/uploads`. |
| Probes | `GET /api/v1/health` for startup (every 5 s, up to 30 failures), readiness (every 5 s) and liveness (every 10 s). |
| Resources | Requests 100m CPU and 256Mi memory; limits 500m CPU and 512Mi memory. |
| Security context | `runAsNonRoot: true`, user and group ID `999`, `fsGroup: 999` (so the mounted volume is group-writable), `fsGroupChangePolicy: OnRootMismatch`. |

## 9. Deploy the worker

```bash
kubectl apply -f k8s/worker.yaml
kubectl rollout status deployment/netscope-worker -n netscope
```

`netscope-worker` runs `celery -A wsgi:celery_app worker --loglevel=info --concurrency=1`. Concurrency is set to 1 to match the container's CPU limit of one core; packet analysis is CPU-bound, so more processes would only compete for the same CPU.

It uses the same init containers, configuration, Secret values, `uploads-pvc` mount and security context as the web pod. Resources: requests 200m CPU and 256Mi memory, limits 1 CPU and 1Gi. The worker has no probes and no Service, because it only consumes tasks from Valkey.

## 10. Verify the deployment

Check that every resource is healthy:

```bash
kubectl get all,pvc -n netscope
kubectl logs deployment/netscope-worker -n netscope
```

The worker log should show a successful connection to Valkey and list the `netscope.analyze_capture` task.

Forward the web Service to your machine:

```bash
kubectl port-forward -n netscope service/netscope-web 8001:8000
```

In a second terminal, check the health endpoint:

```bash
curl -i http://localhost:8001/api/v1/health
```

Expected: HTTP 200 with `{"status": "healthy"}`. The web interface is then available at <http://localhost:8001>.

### End-to-end test

The following script registers a throw-away account, uploads a capture, and polls its status. It uses the documented API (CSRF token from `GET /auth/csrf`, sent as `X-CSRFToken`). Replace `sample.pcap` with any PCAP or PCAPNG file. It needs `curl` and `jq`, and assumes the port-forward above is running.

```bash
BASE=http://localhost:8001/api/v1
JAR=$(mktemp)
csrf() { curl -s -b "$JAR" -c "$JAR" "$BASE/auth/csrf" | jq -r .csrf_token; }

EMAIL="e2e-$(date +%s)@example.com"
PASSWORD="$(openssl rand -hex 12)"

# Register (also signs the account in)
curl -s -b "$JAR" -c "$JAR" -H "X-CSRFToken: $(csrf)" \
  -H "Content-Type: application/json" \
  -d "{\"email\":\"$EMAIL\",\"password\":\"$PASSWORD\"}" "$BASE/auth/register"

# Upload; analysis is queued automatically
ID=$(curl -s -b "$JAR" -c "$JAR" -H "X-CSRFToken: $(csrf)" \
  -F file=@sample.pcap "$BASE/captures" | jq -r .capture.id)

# Poll until the status is completed or failed
curl -s -b "$JAR" "$BASE/captures/$ID/status" | jq
```

`NETSCOPE_ENV` is `production`, so the session cookie is marked `Secure`; the script relies on `curl` sending it to `http://localhost`. Browsers may not send a `Secure` cookie over plain HTTP, so sign-in through the web interface over the port-forward is not guaranteed to work; use the script, or terminate HTTPS in front of the Service.

**Verified result.** With a test capture, the end-to-end run completed in the cluster:

| Field | Result |
|---|---|
| Capture status | `completed` |
| Packets analysed | 531 |
| Flows identified | 25 |
| Worker execution time | 0.285 s |
| Error message | `null` |

This confirms that the web application, the shared upload volume, PostgreSQL, Valkey, Celery and Scapy work together inside the cluster.

## 11. Enable autoscaling (HPA)

The web Deployment can scale between one and five replicas based on CPU utilisation. Only `netscope-web` is autoscaled; PostgreSQL, Valkey and the Celery worker keep a fixed single replica.

**Prerequisite: Metrics Server.** HPA needs the Kubernetes Metrics API. Confirm it is running and returning data:

```bash
kubectl get deployment metrics-server -n kube-system
kubectl top nodes
kubectl top pods -n netscope
```

**CPU requests must be set.** CPU utilisation is measured as a percentage of the container's CPU *request*. `web.yaml` requests `100m`, so the 50% target below corresponds to about 50m of CPU per pod. Without a CPU request, a CPU-based HPA cannot compute utilisation.

Apply `k8s/hpa.yaml`:

```yaml
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: netscope-web-hpa
  namespace: netscope
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: netscope-web

  minReplicas: 1
  maxReplicas: 5

  metrics:
    - type: Resource
      resource:
        name: cpu
        target:
          type: Utilization
          averageUtilization: 50
```

```bash
kubectl apply -f k8s/hpa.yaml
kubectl get hpa -n netscope
kubectl describe hpa netscope-web-hpa -n netscope
```

| Setting | Value | Meaning |
|---|---|---|
| `autoscaling/v2` | API version | Supports configurable resource metrics and scaling behaviour. |
| `scaleTargetRef` | Deployment `netscope-web` | The workload that is scaled. |
| `minReplicas` / `maxReplicas` | 1 / 5 | Scaling bounds. |
| `averageUtilization` | 50 | Target average CPU as a percentage of the CPU request. |

Kubernetes computes the desired replica count as `ceil(currentReplicas × currentUtilization ÷ targetUtilization)`, within the configured bounds. For example, two replicas averaging 100% CPU against a 50% target give `ceil(2 × 100 ÷ 50) = 4`. No custom `behavior` is configured, so default scaling policies apply, including a scale-down stabilisation window of 300 seconds that prevents rapid fluctuations.

In the verified cluster the HPA reported `cpu: 1%/50%` at idle, and `describe` showed the condition `ScalingActive True ValidMetricFound`, confirming that metrics were available.

> **Note:** `web.yaml` sets `replicas: 1`. Re-applying that manifest while the HPA has scaled the Deployment resets the replica count to 1, after which the HPA scales it up again if load persists.

## 12. Load test with Locust

[Locust](https://locust.io/) simulates concurrent HTTP users. It is kept in its own virtual environment so its dependencies (such as `gevent`) cannot conflict with the NetScope application's. The environment directory is git-ignored:

```gitignore
# Locust virtual environment
.venv-locust/
```

```bash
python3 -m venv .venv-locust
source .venv-locust/bin/activate
pip install locust
```

The version used for the recorded test was Locust 2.47.0.

The test script is `load-testing/locustfile.py`:

```python
from locust import HttpUser, task, between


class NetScopeUser(HttpUser):
    wait_time = between(0.1, 0.5)

    @task
    def health_check(self):
        self.client.get("/api/v1/health")
```

Each simulated user requests `GET /api/v1/health` and waits 0.1 to 0.5 seconds between requests. The health endpoint was chosen because it is lightweight and has no side effects: it does not create database records, upload captures or queue Celery tasks. The test therefore exercises the web tier's HTTP handling only, not capture analysis.

**Run the test.** In terminal 1, forward the web Service to local port 8000:

```bash
kubectl port-forward -n netscope service/netscope-web 8000:8000
```

In terminal 2, start Locust:

```bash
source .venv-locust/bin/activate
locust -f load-testing/locustfile.py --host http://127.0.0.1:8000
```

Open <http://localhost:8089> and start a run. The recorded test used:

| Parameter | Value |
|---|---|
| Simulated users | 50 |
| Spawn rate | 5 users per second |
| Duration | approximately 2 minutes |
| Endpoint | `/api/v1/health` |

In two more terminals, watch the autoscaler and the pods:

```bash
kubectl get hpa -n netscope --watch
kubectl get pods -n netscope -w
```

### Observed autoscaling

HPA output recorded during the test:

| CPU (current / target) | Replicas |
|---|---|
| 1% / 50% | 1 |
| 79% / 50% | 1 |
| 79% / 50% | 2 |
| 236% / 50% | 2 |
| 236% / 50% | 4 |
| 236% / 50% | 5 |

The Deployment scaled from 1 to 2 to 4 to 5 replicas (the configured maximum) without any manual `kubectl scale`. All five web pods reached `1/1 Running` with zero restarts. Each new pod went through the same init containers (wait for PostgreSQL and Valkey) and startup probe as the original.

After the load stopped, the HPA initially still showed five replicas although CPU had dropped to 1%. This is expected during the 300-second scale-down stabilisation window. A later check showed `cpu: 1%/50%` with one replica, so the Deployment scaled back down automatically.

### Locust results

| Measurement | Result |
|---|---|
| Total requests | 18,009 |
| Requests per second | 164.9 |
| Failed requests | 3,871 (21.49%) |
| Median response time | 18 ms |
| Average response time | 20.93 ms |
| 95th percentile | 54 ms |
| 99th percentile | 76 ms |
| Maximum | 155 ms |

### Interpretation notes

- **The failure rate is real and not yet explained.** 3,871 of 18,009 requests failed. The `kubectl port-forward` process was seen to be interrupted during the session, but that has not been established as the cause. The Locust *Failures* tab has not been analysed yet. Report this test as demonstrating autoscaling, not as a validated reliability result.
- **Port-forwarding is not load balancing.** `kubectl port-forward` to a Service connects to a single backing pod and keeps the tunnel to that pod. Traffic sent through it is therefore not spread across the replicas that the HPA adds, so these figures describe load on one pod, and the added pods did not receive Locust traffic. To measure request distribution and scaled throughput, send the load to the Service from inside the cluster or through a cluster entry point (for example a NodePort or an Ingress). Neither is configured here.
- **Scope of the test.** Only the stateless health endpoint was exercised. Upload, analysis and database-heavy paths were not load-tested.
- **Shared dependencies.** All web replicas use the same PostgreSQL instance, Valkey broker and `uploads-pvc`. Scaling web pods does not scale those.

## Operations

| Task | Command |
|---|---|
| Show pods | `kubectl get pods -n netscope` |
| Follow web logs | `kubectl logs -f deployment/netscope-web -n netscope` |
| Follow worker logs | `kubectl logs -f deployment/netscope-worker -n netscope` |
| Show autoscaler status | `kubectl get hpa -n netscope` |
| Watch scaling live | `kubectl get hpa -n netscope --watch` |
| Inspect a failing pod | `kubectl describe pod <pod-name> -n netscope` |
| Restart after loading a new image | `minikube image load netscope:local` then `kubectl rollout restart deployment/netscope-web deployment/netscope-worker -n netscope` |

Remember to rerun the migration Job (step 7) when the new image contains new migrations.

**Removing the deployment.** `kubectl delete namespace netscope` deletes every NetScope resource, including the PVCs `uploads-pvc` and `postgres-data-postgres-0`, and therefore the database and uploaded captures unless your StorageClass retains the volumes. Back up what you need first.

## Troubleshooting

| Symptom | What to check |
|---|---|
| `ErrImageNeverPull`, `ErrImagePull` or `ImagePullBackOff` | The image is not in the cluster. Run `minikube image load netscope:local`; the manifests use `imagePullPolicy: IfNotPresent` and do not pull from a registry. |
| `CreateContainerConfigError` or a missing-secret event | `netscope-secrets` does not exist, or lacks `POSTGRES_PASSWORD` or `NETSCOPE_SECRET_KEY` (step 2). |
| Pod stuck in `Init:0/2` | The init containers are waiting for PostgreSQL or Valkey. Check `kubectl get pods -n netscope` and the logs of those pods. |
| Migration Job fails | `kubectl logs job/netscope-migration -n netscope`. Typical causes: PostgreSQL not ready, or a password that no longer matches the one the existing data volume was initialised with. |
| Pod `Pending` with volume messages | `kubectl get pvc -n netscope` and `kubectl describe pvc <name> -n netscope`; confirm a `standard` StorageClass exists. |
| HPA shows `<unknown>` for CPU | Metrics Server is not running or not ready (`kubectl top pods -n netscope`), or the web container has no CPU request. Check `kubectl describe hpa netscope-web-hpa -n netscope`. |
| Replicas stay high after a load test | Expected for about five minutes: the default scale-down stabilisation window is 300 seconds. |
| Captures stay `pending` | The worker is not running or cannot reach Valkey; check the worker logs and that the `valkey` Service has an endpoint. |

## Current scope

Implemented: namespace, configuration, Secret-based credentials, persistent storage, PostgreSQL, Valkey, migration Job, web and worker deployments, health probes on the web pod, resource requests and limits, non-root web and worker pods, CPU-based Horizontal Pod Autoscaling of the web Deployment (1 to 5 replicas, 50% CPU target), a Locust load-test script, and the verified end-to-end analysis and scaling runs above.

Not implemented yet: autoscaling of the Celery worker, load tests of upload and analysis paths, investigation of the load-test failures, Ansible automation, an Ingress, and TLS. PostgreSQL, Valkey and the worker run as single replicas.

One constraint to keep in mind when scaling: `uploads-pvc` uses `ReadWriteOnce`, which restricts the volume to pods on one node. This works on a single-node Minikube cluster, where all five web replicas ran; spreading web replicas across several nodes would require storage that supports `ReadWriteMany`.