# TLSPROXY with a [Trusted Platform Module](https://en.wikipedia.org/wiki/Trusted_Platform_Module) (TPM)

TLSPROXY can use hardware-backed cryptographic keys on devices that have a TPM.

When this feature is enabled, hardware-backed cryptographic keys are used to:
  * encrypt local data (the data cannot be used or recovered on a different device),
  * sign authentication tokens,
  * sign the PKI certificates, OCSP responses, and CRLs.

To enable this feature, set `hwBacked: true` in config.yaml. This option cannot
be changed without manually deleting the entire cache directory.

The TLSPROXY process needs access to `/dev/tpm0` and/or `/dev/tpmrm0` on linux.

## Docker

On docker, use `--device /dev/tpmrm0:/dev/tpmrm0:rwm` and make sure the
container's userid has access to `/dev/tpmrm0`.
