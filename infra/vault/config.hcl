ui = true

storage "file" {
  path = "/vault/data"
}

listener "tcp" {
  address     = "0.0.0.0:8200"
  tls_disable = true   # dev only — enable TLS in prod with cert-manager
}

api_addr = "http://0.0.0.0:8200"
