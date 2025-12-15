# Azure Key Vault Premium & HSM Setup Guide

This guide explains how to set up an Azure Key Vault (Premium SKU) and create HSM-backed keys for use with the Go application.

## 1. Prerequisites
- Azure CLI installed (`az`).
- Logged in (`az login`).

## 2. Create Resource Group and Key Vault
Create a Premium Key Vault to enable HSM-protected keys.

```bash
# Set variables
export RG_NAME="rg-keyvault-demo"
export LOCATION="eastus"
export VAULT_NAME="kv-my-premium-vault" # Must be globally unique

# Create Resource Group
az group create --name $RG_NAME --location $LOCATION

# Create Premium Key Vault
az keyvault create --name $VAULT_NAME --resource-group $RG_NAME --location $LOCATION --sku premium
```

## 3. Create HSM Keys
Create `RSA-HSM` keys. These keys are generated and stored inside the Hardware Security Module.

### A. Create Signing Key (KKP Private Key - Sign)
```bash
az keyvault key create \
  --vault-name $VAULT_NAME \
  --name kkp-private-key-sign \
  --kty RSA \
  --size 2048 \
  --ops sign verify
```

### B. Create Decryption Key (KKP Private Key - Decrypt)
```bash
az keyvault key create \
  --vault-name $VAULT_NAME \
  --name kkp-private-key-decrypt \
  --kty RSA \
  --size 2048 \
  --ops decrypt encrypt wrapKey unwrapKey
```

### C. Create BOT Key (BOT Public Key - Encrypt/Verify)
This key represents the BOT's key. We create it in our Vault to simulate the BOT's side or to use AKV for encryption/verification.
```bash
az keyvault key create \
  --vault-name $VAULT_NAME \
  --name bot-public-key-encrypt \
  --kty RSA \
  --size 2048 \
  --ops encrypt decrypt wrapKey unwrapKey verify sign
```

## 5. Grant Permissions
Ensure your user (and the Go app) has permissions.
If using RBAC (recommended):
```bash
export USER_ID=$(az ad signed-in-user show --query id -o tsv)

# Key Vault Crypto Officer (allows Sign, Decrypt, etc.)
az role assignment create --role "Key Vault Crypto Officer" --assignee $USER_ID --scope "/subscriptions/<sub-id>/resourceGroups/$RG_NAME/providers/Microsoft.KeyVault/vaults/$VAULT_NAME"

# Key Vault Secrets User (allows Get Secret)
az role assignment create --role "Key Vault Secrets User" --assignee $USER_ID --scope "/subscriptions/<sub-id>/resourceGroups/$RG_NAME/providers/Microsoft.KeyVault/vaults/$VAULT_NAME"
```

If using Access Policies:
```bash
az keyvault set-policy --name $VAULT_NAME --upn <your-email> --key-permissions get list sign decrypt --secret-permissions get list
```

## 6. How it Works (Under the Hood)

### Signing (JWS)
1.  **Local**: The Go app takes the data and calculates a SHA-256 hash.
2.  **Remote**: The app sends **only the hash** to Azure Key Vault.
3.  **HSM**: The Vault uses the `RSA-HSM` private key to sign the hash. The private key **never** leaves the HSM.
4.  **Result**: The signature is returned to the app to construct the JWS.

### Encryption (JWE)
1.  **Local**: The Go app retrieves the "BOT Public Key" (from Secrets or Keys).
2.  **Local**: The app generates a random Content Encryption Key (CEK).
3.  **Local**: The app encrypts the data with the CEK (AES-GCM).
4.  **Local**: The app encrypts the CEK with the Public Key (RSA-OAEP).
5.  **Result**: A JWE is created. **No interaction with the Private Key is needed for encryption.**

### Decryption (JWE)
1.  **Local**: The Go app parses the JWE and extracts the Encrypted CEK.
2.  **Remote**: The app sends the Encrypted CEK to Azure Key Vault.
3.  **HSM**: The Vault uses the `RSA-HSM` private key to decrypt (unwrap) the CEK. The private key **never** leaves the HSM.
4.  **Result**: The raw CEK is returned to the app.
5.  **Local**: The app uses the CEK to decrypt the payload.
