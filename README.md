# CACApp - Common Access Card Management & Validation Tool

A comprehensive Windows application for reading, validating, managing, and monitoring Common Access Cards (CAC) and other X.509 certificates. This tool provides advanced certificate chain validation, revocation checking, and certificate lifecycle management for DoD, Government, Military, and Contractor certificates.

## 🎯 Overview

CACApp is a full-featured certificate management application designed to help users interact with smart card readers, validate certificate chains, check revocation status, and manage certificates efficiently. It distinguishes between real certificate revocations and network connectivity issues, providing clear feedback on certificate validity.

## ✨ Key Features

### 🔐 Smart Card Reading
- **Multi-Reader Support**: Detect and work with multiple smart card readers
- **CAC Card Reading**: Read certificates directly from Common Access Cards
- **PIN Entry**: Secure PIN entry interface for card authentication
- **Reader Management**: Refresh and select from available readers

### ✅ Certificate Validation
- **Online Chain Validation**: Validate certificate chains with online revocation checking (OCSP/CRL)
- **Offline Fallback**: Automatic offline validation when online checks fail
- **Smart Revocation Detection**: Distinguishes between:
  - 🔌 **Connectivity Issues**: Network problems preventing OCSP/CRL access (certificate is valid)
  - 🚫 **Real Revocation**: Confirmed revocation by both online and offline checks
- **DoD Certificate Validation**: Specialized validation for Government/Military/Contractor certificates
- **Certificate Category Detection**: Automatically identifies certificate type (Military, Government, Contractor, DoD)

### 🔗 Certificate Chain Analysis
- **Full Chain Display**: View complete certificate chain with all intermediate certificates
- **Chain Validation**: Verify certificate chain integrity
- **Certificate Details**: View subject, issuer, validity dates, thumbprints for each certificate in the chain
- **Error Reporting**: Detailed error messages for chain validation failures

### 📊 CRL/OCSP Monitoring
- **CRL Status Checking**: Check Certificate Revocation List (CRL) availability and response times
- **OCSP Status Checking**: Verify Online Certificate Status Protocol (OCSP) server accessibility
- **Response Time Metrics**: Monitor CRL/OCSP server performance
- **Revocation Status**: Real-time revocation status from OCSP servers
- **Distribution Point Discovery**: Automatically find and test all CRL/OCSP endpoints

### 💾 Certificate Storage & Management
- **Local Storage**: Store certificates locally for future reference
- **Certificate Search**: Advanced search and filtering by:
  - Subject name
  - Issuer
  - Thumbprint
  - Validity dates
  - Active/Expired status
- **Expiration Tracking**: Identify certificates expiring soon (90-day warning)
- **Certificate List**: View all stored certificates with key information

### 📤 Certificate Export
- **Multiple Formats**: Export certificates in various formats:
  - **PEM**: Base64-encoded certificate (`.pem`)
  - **DER**: Binary certificate format (`.der`)
  - **PFX**: Password-protected certificate with private key (`.pfx`)
- **Secure Export**: Password protection for PFX exports

### 📥 Certificate Import
- **Multiple Formats**: Import certificates from:
  - PEM (`.pem`)
  - DER (`.der`)
  - PFX/P12 (`.pfx`, `.p12`)
  - CRT/CER (`.crt`, `.cer`)
- **Password Support**: Secure import of password-protected certificates

### 📋 Detailed Certificate Information
- **Comprehensive Details**: View extensive certificate information including:
  - Subject and Issuer Distinguished Names
  - Validity period (Not Before / Not After)
  - Serial number and thumbprint
  - Public key algorithm and key size
  - Key usage flags
  - Extended key usage
  - Subject Alternative Names (SAN)
  - Certificate policies
  - CRL Distribution Points
  - OCSP URLs
  - Subject and Issuer name parts breakdown

## 🛠️ Technology Stack

### Backend
- **.NET 9.0** (Windows-specific)
- **ASP.NET Core Web API**
- **C#** with Windows Smart Card API integration
- **Serilog** for structured logging
- **Swagger/OpenAPI** for API documentation

### Frontend
- **Angular 19** (Standalone components)
- **TypeScript**
- **Bootstrap 5.3** for UI styling
- **RxJS** for reactive programming

## 📋 Requirements

### System Requirements
- **OS**: Windows 10/11 (64-bit)
- **.NET Runtime**: .NET 9.0 Runtime
- **Smart Card Reader**: USB smart card reader with drivers installed
- **Windows Smart Card Service**: Must be running

### Software Dependencies
- Node.js 18+ (for frontend development)
- npm or yarn (for frontend dependencies)

## 🚀 Installation

### Prerequisites
1. Install [.NET 9.0 SDK](https://dotnet.microsoft.com/download/dotnet/9.0)
2. Install [Node.js](https://nodejs.org/) (v18 or higher)
3. Ensure Windows Smart Card service is running:
   ```powershell
   sc query SCardSvr
   ```

### Build Steps

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd CACApp
   ```

2. **Build the backend**
   ```bash
   dotnet restore
   dotnet build
   ```

3. **Install frontend dependencies**
   ```bash
   cd ClientApp
   npm install
   cd ..
   ```

4. **Run the application**
   ```bash
   # Terminal 1: Start backend API
   dotnet run
   
   # Terminal 2: Start frontend (in ClientApp directory)
   cd ClientApp
   npm start
   ```

5. **Access the application**
   - Frontend: http://localhost:4200
   - API Swagger UI: http://localhost:5000/swagger (or check `launchSettings.json` for actual port)

## 📖 Usage

### Reading a CAC Card
1. Insert your CAC card into the smart card reader
2. Click "🔄 Refresh Readers" to detect available readers
3. Select your reader from the dropdown
4. Click "📥 Read CAC Card"
5. Enter your PIN when prompted
6. View certificate information in the Certificate Information panel

### Validating Certificates
- **Validate Chain**: Click "🔗 Validate Certificate Chain" to verify the certificate chain
- **Validate Online**: Click "🌐 Validate Online" for DoD/GOVT/Military validation with online revocation checking
- Review validation results in the respective panels

### Checking Revocation Status
1. Read a certificate from your CAC card
2. Click "🔍 Check CRL/OCSP Status"
3. View detailed status including:
   - CRL accessibility and response times
   - OCSP server status
   - Revocation status (Valid/Revoked/Not Available)

### Storing Certificates
1. Read a certificate from your CAC card
2. Click "💾 Store Certificate"
3. Access stored certificates from the "Stored Certificates" panel
4. Use search filters to find specific certificates

### Exporting Certificates
1. Read a certificate from your CAC card
2. Click "💾 Export" dropdown
3. Select format (PEM, DER, or PFX)
4. For PFX, enter a password when prompted
5. Certificate file will be downloaded

### Importing Certificates
1. Click "📤 Import Certificate"
2. Select certificate file (PEM, DER, PFX, etc.)
3. Enter password if required
4. Certificate will be loaded and displayed

## 🏗️ Architecture

### Backend Structure
```
CACApp/
├── Controllers/          # API endpoints
│   ├── CacReaderController.cs
│   ├── CacValidationController.cs
│   ├── CertificateController.cs
│   ├── CertificateExportController.cs
│   ├── CertificateStorageController.cs
│   └── CrlOcspMonitoringController.cs
├── Services/             # Business logic
│   ├── CacReaderService.cs
│   ├── CacValidationService.cs
│   ├── CertificateService.cs
│   ├── CertificateExportService.cs
│   ├── CertificateStorageService.cs
│   └── CrlOcspMonitoringService.cs
└── Models/              # Data models
```

### Frontend Structure
```
ClientApp/src/app/
├── components/          # Reusable components
│   ├── pin-entry/
│   └── password-prompt/
├── home/               # Main application component
├── services/          # Angular services
│   ├── cac-reader.service.ts
│   ├── cac-validation.service.ts
│   ├── certificate.service.ts
│   ├── certificate-storage.service.ts
│   ├── certificate-export.service.ts
│   └── crl-ocsp-monitoring.service.ts
```

## 🔌 API Documentation

The application includes Swagger/OpenAPI documentation. When running, access:
- **Swagger UI**: `http://localhost:<port>/swagger`

### Key API Endpoints

#### CAC Reader
- `GET /api/cac-reader/readers` - Get available smart card readers
- `POST /api/cac-reader/read` - Read certificate from CAC card

#### Certificate Validation
- `POST /api/cac-validation/validate-online` - Validate CAC certificate online
- `POST /api/certificate/validate-chain` - Validate certificate chain
- `POST /api/certificate/chain-info` - Get detailed chain information
- `POST /api/certificate/details` - Get comprehensive certificate details

#### CRL/OCSP Monitoring
- `POST /api/crl-ocsp-monitoring/check-status` - Check CRL/OCSP status

#### Certificate Storage
- `GET /api/certificate-storage/list` - List stored certificates
- `POST /api/certificate-storage/store` - Store a certificate
- `POST /api/certificate-storage/search` - Search stored certificates
- `DELETE /api/certificate-storage/{index}` - Delete stored certificate

#### Certificate Export
- `POST /api/certificate-export/export` - Export certificate in various formats

## 🔍 Understanding Revocation Status

The application intelligently distinguishes between different revocation scenarios:

### 🔌 Connectivity Issue (False Positive)
When online revocation check reports "REVOKED" but offline validation succeeds:
- **Status**: Certificate is **VALID**
- **Message**: "🔌 CONNECTIVITY ISSUE: Online revocation check reported REVOKED, but offline validation succeeded. This indicates a network/connectivity problem preventing access to OCSP/CRL servers, NOT an actual revocation."
- **Action**: Certificate can be used safely

### 🚫 Real Revocation
When both online and offline checks confirm revocation:
- **Status**: Certificate is **REVOKED**
- **Message**: "🚫 REAL REVOCATION: [Certificate details] - Reason: [Revocation reason] (Confirmed by both online and offline checks)"
- **Action**: Certificate should not be used

### ⚠️ Status Unknown
When revocation status cannot be determined:
- **Status**: Certificate is **VALID** (if chain is otherwise valid)
- **Message**: "🔌 CONNECTIVITY ISSUE: Revocation status could not be verified online"
- **Action**: Certificate can be used, but revocation status is uncertain

## 🐛 Troubleshooting

### No Readers Found
- Ensure smart card reader is connected via USB
- Install latest drivers for your reader
- Verify Windows Smart Card service is running:
  ```powershell
  sc query SCardSvr
  ```
- Try restarting the Windows Smart Card service:
  ```powershell
  net stop SCardSvr
  net start SCardSvr
  ```

### Certificate Read Fails
- Verify PIN is correct
- Ensure card is properly inserted
- Check card reader drivers are installed
- Try a different reader if available

### Validation Fails
- Check internet connectivity (for online validation)
- Verify firewall allows OCSP/CRL access
- Review error messages in validation result panel
- Check certificate expiration dates

### CRL/OCSP Not Available
- Verify network connectivity
- Check firewall/proxy settings
- Ensure DoD network access if required
- Review CRL/OCSP URLs in certificate details

## 📝 Logging

The application uses Serilog for structured logging:
- **Log Location**: `logs/cacapp-YYYYMMDD.log`
- **Log Levels**: Debug, Information, Warning, Error
- **Log Format**: Structured JSON with timestamps

## 🔒 Security Considerations

- **PIN Entry**: PINs are handled securely and not logged
- **Password Protection**: PFX exports require password protection
- **Local Storage**: Certificates are stored locally in user's AppData folder
- **No Network Transmission**: Private keys never leave the local machine
- **Certificate Validation**: Always validates certificate chains before use

## 📄 License

See [LICENSE](LICENSE) file for details.

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## 📧 Support

For issues, questions, or feature requests, please open an issue on the GitHub repository.

---

**Note**: This application is designed for use with DoD Common Access Cards and other X.509 certificates. Ensure you have proper authorization before reading or validating certificates.
