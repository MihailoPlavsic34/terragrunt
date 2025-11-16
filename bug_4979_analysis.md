# Bug #4979 Analysis: TG_DEPENDENCY_FETCH_OUTPUT_FROM_STATE Not Using Backend Role

## Summary
When `TG_DEPENDENCY_FETCH_OUTPUT_FROM_STATE=true` is set, Terragrunt fails to assume the role specified in the `remote_state.config.assume_role` block when fetching dependency outputs directly from S3. Instead, it uses credentials already present in the environment, causing AccessDenied errors.

## Expected Behavior
- **ROLE_A**: Used for IaC operations (plan/apply) via provider configuration
- **ROLE_B**: Used for fetching remote state via `remote_state.config.assume_role`
- When fetching dependency outputs, Terragrunt should assume ROLE_B to read the state file

## Actual Behavior
- With `TG_DEPENDENCY_FETCH_OUTPUT_FROM_STATE=true`, Terragrunt uses ROLE_A instead of ROLE_B
- This causes AccessDenied: `User: arn:aws:sts::XXX:assumed-role/ROLE_A/...` is not authorized to perform `s3:GetObject`

---

## Root Cause: Regression from AWS SDK v1 to v2 Migration

The bug was introduced during the migration from AWS SDK v1 to v2. The credential precedence logic was **inverted**.

### ✅ Working Code (v0.79.3 - AWS SDK v1)

**File:** `awshelper/config.go` (lines 95-119)

```go
func CreateAwsSessionFromConfig(config *AwsSessionConfig, opts *options.TerragruntOptions) (*session.Session, error) {
    // ... session setup ...

    // Merge the config based IAMRole options into the original one, 
    // as the config has higher precedence than CLI.
    iamRoleOptions := opts.IAMRoleOptions
    if config.RoleArn != "" {
        iamRoleOptions = options.MergeIAMRoleOptions(
            iamRoleOptions,
            options.IAMRoleOptions{
                RoleARN:               config.RoleArn,
                AssumeRoleSessionName: config.SessionName,
            },
        )
    }

    if iamRoleOptions.WebIdentityToken != "" && iamRoleOptions.RoleARN != "" {
        sess.Config.Credentials = getWebIdentityCredentialsFromIAMRoleOptions(sess, iamRoleOptions)
        return sess, nil
    }

    credentialOptFn := func(p *stscreds.AssumeRoleProvider) {
        if config.ExternalID != "" {
            p.ExternalID = aws.String(config.ExternalID)
        }
    }

    // ✅ CORRECT: If role ARN exists, assume it. Otherwise, use env creds.
    if iamRoleOptions.RoleARN != "" {
        sess.Config.Credentials = getSTSCredentialsFromIAMRoleOptions(sess, iamRoleOptions, credentialOptFn)
    } else if creds := getCredentialsFromEnvs(opts); creds != nil {
        sess.Config.Credentials = creds
    }

    return sess, nil
}
```

**Key Logic:**
```
IF role_arn_from_config EXISTS:
    → Assume that role (ROLE_B)
ELSE IF env_credentials_exist:
    → Use env credentials (ROLE_A)
```

This correctly prioritizes the `remote_state.config.assume_role` over environment credentials.

---

### ❌ Broken Code (Current - AWS SDK v2)

**File:** `internal/awshelper/config.go` (lines 85-147)

```go
func CreateAwsConfig(
    ctx context.Context,
    l log.Logger,
    awsCfg *AwsSessionConfig,
    opts *options.TerragruntOptions,
) (aws.Config, error) {
    var configOptions []func(*config.LoadOptions) error

    configOptions = append(configOptions, config.WithAppID("terragrunt/"+version.GetVersion()))

    // Add env credentials to config if they exist
    if envCreds := createCredentialsFromEnv(opts); envCreds != nil {
        l.Debugf("Using AWS credentials from auth provider command")
        configOptions = append(configOptions, config.WithCredentialsProvider(envCreds))
    } else if awsCfg != nil && awsCfg.CredsFilename != "" {
        configOptions = append(configOptions, config.WithSharedConfigFiles([]string{awsCfg.CredsFilename}))
    }

    // ... region and profile configuration ...

    cfg, err := config.LoadDefaultConfig(ctx, configOptions...)
    if err != nil {
        return aws.Config{}, errors.Errorf("Error loading AWS config: %w", err)
    }

    // ❌ BUG: Return early if env credentials exist, never check for role assumption
    if createCredentialsFromEnv(opts) != nil {
        return cfg, nil  // ← RETURNS HERE WITH ROLE_A
    }

    // This code is never reached when env credentials exist
    iamRoleOptions := getMergedIAMRoleOptions(awsCfg, opts)
    if iamRoleOptions.RoleARN == "" {
        return cfg, nil
    }

    if iamRoleOptions.WebIdentityToken != "" {
        l.Debugf("Assuming role %s using WebIdentity token", iamRoleOptions.RoleARN)
        cfg.Credentials = getWebIdentityCredentialsFromIAMRoleOptions(cfg, iamRoleOptions)
        return cfg, nil
    }

    l.Debugf("Assuming role %s", iamRoleOptions.RoleARN)
    cfg.Credentials = getSTSCredentialsFromIAMRoleOptions(cfg, iamRoleOptions, getExternalID(awsCfg))

    return cfg, nil
}
```

**Key Logic:**
```
IF env_credentials_exist:
    → Use env credentials (ROLE_A) and RETURN EARLY
    → Never check for role_arn_from_config

IF role_arn_from_config EXISTS:
    → Assume that role (ROLE_B)  ← NEVER REACHED
```

This incorrectly prioritizes environment credentials over `remote_state.config.assume_role`.

---

## The Execution Flow

### Scenario: User has ROLE_A in environment, ROLE_B in remote_state config

**Call Stack:**
1. `getTerragruntOutputJSONFromRemoteStateS3()` (config/dependency.go:958)
2. `s3ConfigExtended.GetAwsSessionConfig()` → Returns config with ROLE_B
3. `awshelper.CreateS3Client(ctx, l, sessionConfig, opts)` 
   - `sessionConfig` contains ROLE_B
   - `opts` contains ROLE_A in environment
4. `CreateAwsConfig()` checks env credentials first
5. **Returns early with ROLE_A, never assumes ROLE_B**

### What Should Happen:
The function should check if `awsCfg.RoleArn` (ROLE_B) is set **before** deciding to use env credentials (ROLE_A).

---

## The Fix

**File:** `internal/awshelper/config.go`

```go
func CreateAwsConfig(
    ctx context.Context,
    l log.Logger,
    awsCfg *AwsSessionConfig,
    opts *options.TerragruntOptions,
) (aws.Config, error) {
    var configOptions []func(*config.LoadOptions) error

    configOptions = append(configOptions, config.WithAppID("terragrunt/"+version.GetVersion()))

    if envCreds := createCredentialsFromEnv(opts); envCreds != nil {
        l.Debugf("Using AWS credentials from auth provider command")
        configOptions = append(configOptions, config.WithCredentialsProvider(envCreds))
    } else if awsCfg != nil && awsCfg.CredsFilename != "" {
        configOptions = append(configOptions, config.WithSharedConfigFiles([]string{awsCfg.CredsFilename}))
    }

    // Prioritize configured region over environment variables
    var region string
    if awsCfg != nil && awsCfg.Region != "" {
        region = awsCfg.Region
    } else {
        region = getRegionFromEnv(opts)
    }

    if region == "" {
        region = "us-east-1"
    }

    configOptions = append(configOptions, config.WithRegion(region))

    if awsCfg != nil && awsCfg.Profile != "" {
        configOptions = append(configOptions, config.WithSharedConfigProfile(awsCfg.Profile))
    }

    cfg, err := config.LoadDefaultConfig(ctx, configOptions...)
    if err != nil {
        return aws.Config{}, errors.Errorf("Error loading AWS config: %w", err)
    }

    // FIX: Check for role assumption BEFORE returning early with env creds
    iamRoleOptions := getMergedIAMRoleOptions(awsCfg, opts)
    
    // If no role to assume and we have env creds, return early
    if iamRoleOptions.RoleARN == "" && createCredentialsFromEnv(opts) != nil {
        return cfg, nil
    }
    
    // If no role to assume at all, return
    if iamRoleOptions.RoleARN == "" {
        return cfg, nil
    }

    if iamRoleOptions.WebIdentityToken != "" {
        l.Debugf("Assuming role %s using WebIdentity token", iamRoleOptions.RoleARN)
        cfg.Credentials = getWebIdentityCredentialsFromIAMRoleOptions(cfg, iamRoleOptions)
        return cfg, nil
    }

    l.Debugf("Assuming role %s", iamRoleOptions.RoleARN)
    cfg.Credentials = getSTSCredentialsFromIAMRoleOptions(cfg, iamRoleOptions, getExternalID(awsCfg))

    return cfg, nil
}
```

### Key Changes:
1. **Move** `getMergedIAMRoleOptions()` call **before** the env credentials check
2. **Only return early** with env credentials if **no role needs to be assumed**
3. **Restore** the v0.79.3 logic: prioritize role assumption over env credentials

---

## Impact

**Affected Users:**
- Use different IAM roles for state access vs. infrastructure operations
- Enable `TG_DEPENDENCY_FETCH_OUTPUT_FROM_STATE` for performance
- Have dependencies between Terragrunt units

**Versions:**
- **Working:** v0.79.3 and earlier (AWS SDK v1)
- **Broken:** v0.88.1, v0.91.1, and likely all versions after AWS SDK v2 migration

---

## Workarounds

Until fixed:
1. **Disable the feature flag** (slower but works):
   ```bash
   unset TG_DEPENDENCY_FETCH_OUTPUT_FROM_STATE
   ```

2. **Grant ROLE_A state read permissions** (security concern):
   - Not recommended as it violates least privilege principle

3. **Use same role for both** (not always possible):
   - Remove `assume_role` from provider config
   - Only use `remote_state.config.assume_role`
