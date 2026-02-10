# IIS Deployment Guide for CAC Card Reader

This guide covers the steps needed to deploy the CAC App to Windows Server 2022 with IIS and ensure the card reader functionality works correctly.

## Common Issues

When deploying to IIS, the card reader may not work due to:
1. **Application Pool Identity** - Default IIS identities don't have smart card hardware access
2. **Smart Card Service** - Must be running and accessible
3. **Scope Context** - IIS requires SYSTEM scope instead of USER scope
4. **Permissions** - Application pool needs proper security permissions

## Solution Steps

### 1. Ensure Smart Card Service is Running

The Windows Smart Card service must be running for card reader access:

```powershell
# Check if service is running
Get-Service SCardSvr

# Start the service if not running
Start-Service SCardSvr

# Set service to automatic startup
Set-Service SCardSvr -StartupType Automatic
```

Or using Command Prompt (as Administrator):
```cmd
sc query SCardSvr
sc start SCardSvr
sc config SCardSvr start= auto
```

### 2. Configure IIS Application Pool Identity

You have two options:

#### Option A: Use a Domain/Service Account (Recommended)

1. Create or use an existing domain account with appropriate permissions
2. In IIS Manager:
   - Navigate to **Application Pools**
   - Select your application pool
   - Click **Advanced Settings**
   - Under **Process Model** → **Identity**, click **...**
   - Select **Custom account** and enter the domain account credentials
   - Click **OK**

3. Grant the account necessary permissions:
   ```powershell
   # Add to Smart Card Readers group (if exists)
   # Or grant explicit permissions to smart card hardware
   ```

#### Option B: Use Local System Account (Less Secure)

1. In IIS Manager:
   - Navigate to **Application Pools**
   - Select your application pool
   - Click **Advanced Settings**
   - Under **Process Model** → **Identity**, select **LocalSystem**

**Note:** LocalSystem has extensive permissions and should only be used in secure environments.

### 3. Grant Smart Card Hardware Access

The application pool identity needs access to smart card hardware:

```powershell
# Run as Administrator
# Grant access to smart card readers for the application pool identity
# Replace "YourAppPoolIdentity" with your actual identity

# For ApplicationPoolIdentity (IIS AppPool\YourAppPoolName):
icacls "C:\Windows\System32\winscard.dll" /grant "IIS AppPool\YourAppPoolName:RX"

# For a custom account:
icacls "C:\Windows\System32\winscard.dll" /grant "DOMAIN\ServiceAccount:RX"
```

### 4. Verify Smart Card Reader Detection

After deployment, test if readers are detected:

```powershell
# Test from PowerShell (run as the application pool identity)
$context = [System.Runtime.InteropServices.Marshal]::AllocHGlobal(4)
$result = [CACApp.Services.CacReaderService]::SCardEstablishContext(2, [IntPtr]::Zero, [IntPtr]::Zero, [ref]$context)
# Result should be 0 (success)
```

Or use the application's API endpoint:
```
GET https://yourserver/api/cac-reader/readers
```

### 5. Code Changes Applied

The application has been updated to automatically try both USER and SYSTEM scopes:
- First attempts `SCARD_SCOPE_USER` (for logged-in users)
- Falls back to `SCARD_SCOPE_SYSTEM` (for IIS/service accounts)

This allows the same code to work in both development and IIS environments.

### 6. Additional IIS Configuration

#### Enable 32-bit Applications (if needed)
If using 32-bit smart card drivers:
- Application Pool → Advanced Settings → **Enable 32-Bit Applications** → `True`

#### Load User Profile
- Application Pool → Advanced Settings → **Process Model** → **Load User Profile** → `True`

#### Idle Timeout
Consider increasing if card operations take time:
- Application Pool → Advanced Settings → **Process Model** → **Idle Timeout** → `00:20:00` (20 minutes)

### 7. Troubleshooting

#### Check Application Logs
Review the application logs in the `logs` directory for detailed error messages:
```
logs/cacapp-YYYYMMDD.log
```

#### Common Error Codes

- **0x8010000D** or **0x8010006A**: Smart Card service stopped
  - Solution: Start SCardSvr service
  
- **0x8010000E** or **0x80100069**: Smart Card service not available
  - Solution: Ensure service is running and accessible
  
- **0x80100001** or **0x80100002**: No readers available
  - Solution: Check physical connection, drivers, and permissions
  
- **0x80100008**: Sharing violation
  - Solution: Another process is using the reader

#### Test Smart Card Service
```powershell
# Check service status
Get-Service SCardSvr | Format-List *

# Check service dependencies
Get-Service SCardSvr | Select-Object -ExpandProperty DependentServices

# View service logs
Get-EventLog -LogName System -Source "SCardSvr" -Newest 10
```

#### Verify Reader Detection from Command Line
```cmd
# List available readers
scardcli listreaders
```

### 8. Security Considerations

1. **Principle of Least Privilege**: Use a dedicated service account with minimal required permissions
2. **Network Security**: Ensure IIS site uses HTTPS
3. **Access Control**: Restrict access to the application endpoints
4. **Audit Logging**: Monitor access to smart card operations

### 9. Deployment Checklist

- [ ] Smart Card service (SCardSvr) is running and set to automatic
- [ ] Application pool identity has smart card hardware access
- [ ] Application deployed to IIS with correct permissions
- [ ] Application can detect smart card readers via API
- [ ] Logs directory is writable by application pool identity
- [ ] Firewall rules allow necessary ports
- [ ] HTTPS is configured (recommended)

### 10. Testing After Deployment

1. **Test Reader Detection**:
   ```bash
   curl https://yourserver/api/cac-reader/readers
   ```

2. **Check Application Logs**:
   ```powershell
   Get-Content logs\cacapp-*.log -Tail 50
   ```

3. **Verify Service Status**:
   ```powershell
   Get-Service SCardSvr
   ```

## Additional Resources

- [Windows Smart Card API Documentation](https://docs.microsoft.com/en-us/windows/win32/secsmart/smart-card-api)
- [IIS Application Pool Identities](https://docs.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities)
- [Smart Card Troubleshooting](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-b--smart-card-troubleshooting)

## Support

If issues persist after following this guide:
1. Check application logs for specific error codes
2. Verify Smart Card service is running
3. Test with a different application pool identity
4. Ensure smart card drivers are installed on the server
5. Verify physical card reader connection
