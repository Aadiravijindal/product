# Provisions the signing keypair used by the artifact-release pipeline.
# Key material lives ~5 years in KMS; artifacts signed with it live longer.

resource "tls_private_key" "release_signing" {
  algorithm = "RSA"
  rsa_bits  = 2048
}

resource "aws_kms_key" "release" {
  description             = "release artifact signing"
  deletion_window_in_days = 30
}

output "release_public_key" {
  value = tls_private_key.release_signing.public_key_pem
}
