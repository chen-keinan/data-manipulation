# Runtime Reachability

## Run Tracee

```sh
docker run --name tracee -it --rm   --pid=host --cgroupns=host --privileged   -v /etc/os-release:/etc/os-release-host:ro   -v /var/run:/var/run:ro   aquasec/tracee:latest --scope container --events security_file_open --output json > tracee_output.txt
```

## Run nginx

```sh
docker run -it --rm -d -p 8080:80 --name web nginx
```

## Scan Nginx with Trivy

```sh
trivy image nginx --list-all-pkgs --format json > trivy_output.json
```

## Find Reachability

```sh
reachability trivy_output.json tracee_output.txt
```
