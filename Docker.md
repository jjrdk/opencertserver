# Running the Containerized Server

The containerized OpenCertServer provides both the EST and ACME endpoints. The container is configured using command line arguments pointing to the keys to use as root certificates.

The containerized server is available on [Docker Hub](https://hub.docker.com/jjrdk/opencertserver).

## Calling the EST endpoints

To get the server certificate, use the following command:

```bash
curl -k https://localhost:8084/.well-known/est/cacerts
```

## Container Setup

To register the keys as secrets in kubernetes, use the following commands:

```bash
kubectl create secret generic opencertserver-certs --from-file=rsa-cert=rsa-cert.pem --from-file=rsa-privatekey=rsa-privatekey.pem --from-file=ecdsa-cert=ecdsa-cert.pem --from-file=ecdsa-privatekey=ecdsa-privatekey.pem
````

Below is an example kubernetes deployment:

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: opencertserver
spec:
  replicas: 1
  selector:
    matchLabels:
      rs: opencerterver
  template:
    metadata:
      name: opencertserver-deployment
      labels:
        app: opencertserver
        rs: opencertserver
    spec:
      volumes:
      - name: cert-volume
        secret:
          secretName: opencertserver-certs
      containers:
        - name: opencertserver
          image: jjrdk/opencertserver:latest
          args: ["--authority https://identity.reimers.dk --rsa", "/var/lib/cert-volume/rsa-cert", "--rsa-key", "/var/lib/cert-volume/rsa-privatekey","--ec", "/var/lib/cert-volume/ecdsa-cert", "--ec-key", "/var/lib/cert-volume/ecdsa-privatekey"]
          ports:
          - containerPort: 8084
          env:
            - name: ASPNETCORE_URLS
              value: "http://*:8084"
          volumeMounts:
          - name: cert-volume
            readOnly: true
            mountPath: "/var/lib/cert-volume"
          resources:
            requests:
              memory: 64Mi
              cpu: 500m
            limits :
              memory: 256Mi
              cpu: 1000m
          readinessProbe:
            httpGet:
              path: /health
              port: 8084
            initialDelaySeconds: 10
            timeoutSeconds: 30
          livenessProbe:
            httpGet:
              path: /health
              port: 8084
            initialDelaySeconds: 10
            timeoutSeconds: 10
            periodSeconds: 600
```
