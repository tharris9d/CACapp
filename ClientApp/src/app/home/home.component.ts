import { Component, OnInit } from '@angular/core';
import { CommonModule, KeyValuePipe } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { CacReaderService, Certificate } from '../services/cac-reader.service';
import { CertificateService } from '../services/certificate.service';
import { CacValidationService, ValidationResult } from '../services/cac-validation.service';
import { CertificateStorageService, StoredCertificate, CertificateSearchCriteria } from '../services/certificate-storage.service';
import { CrlOcspMonitoringService, CrlOcspStatus, RevocationDistributionPoint } from '../services/crl-ocsp-monitoring.service';
import { CertificateExportService, CertificateExportFormat, CertificateDetails } from '../services/certificate-export.service';
import { PinEntryComponent } from '../components/pin-entry/pin-entry.component';
import { PasswordPromptComponent } from '../components/password-prompt/password-prompt.component';

@Component({
  selector: 'app-home',
  standalone: true,
  imports: [CommonModule, FormsModule, PinEntryComponent, PasswordPromptComponent, KeyValuePipe],
  templateUrl: './home.component.html',
  styleUrl: './home.component.css'
})
export class HomeComponent implements OnInit {
  statusTitle = 'Ready';
  statusDetails = 'Insert your CAC card and click \'Read CAC Card\' to begin';

  availableReaders: string[] = [];
  selectedReader: string | null = null;
  currentCertificate: Certificate | null = null;

  certificateInfo = '';
  chainInfo = '';
  validationResult = '';

  storedCertificates: StoredCertificate[] = [];
  selectedStoredIndex: number | null = null;

  isLoading = false;
  showPinEntry = false;

  crlOcspStatus: CrlOcspStatus | null = null;
  revocationDistributionPoints: RevocationDistributionPoint[] = [];
  showCrlOcspMonitoring = false;

  certificateDetails: CertificateDetails | null = null;
  showCertificateDetails = false;
  showExpiringCertificates = false;
  expiringCertificates: StoredCertificate[] = [];
  searchCriteria: CertificateSearchCriteria = {};
  showSearchFilters = false;
  showPasswordPrompt = false;
  passwordForExport = '';
  pendingExportFormat: CertificateExportFormat | null = null;
  showPasswordPromptForImport = false;
  passwordForImport = '';
  pendingImportFile: File | null = null;
  usePinModal = false; // Toggle for PIN modal vs Windows PIN prompt (default: Windows PIN prompt)

  constructor(
    private cacReaderService: CacReaderService,
    private certificateService: CertificateService,
    private cacValidationService: CacValidationService,
    private certificateStorageService: CertificateStorageService,
    private crlOcspMonitoringService: CrlOcspMonitoringService,
    private certificateExportService: CertificateExportService
  ) { }

  ngOnInit(): void {
    this.loadInitialData();
  }

  loadInitialData(): void {
    this.checkReaders();
    this.loadStoredCertificates();
  }

  checkReaders(): void {
    this.isLoading = true;
    this.updateStatus('Checking Readers', 'Scanning for CAC readers...');

    this.cacReaderService.getAvailableReaders().subscribe({
      next: (response) => {
        this.availableReaders = response.readers || [];
        if (this.availableReaders.length > 0) {
          this.selectedReader = this.availableReaders[0];
          this.updateStatus('Reader Found', `Found ${this.availableReaders.length} reader(s)`);
        } else {
          const errorMsg = response.error || response.message || 'No readers found';
          this.updateStatus('No Readers Found', errorMsg);
          console.warn('No readers found:', response);
        }
        this.isLoading = false;
      },
      error: (err) => {
        const errorMsg = err.error?.message || err.error?.error || err.message || 'Failed to check readers';
        this.updateStatus('Error', errorMsg);
        this.availableReaders = [];
        this.isLoading = false;
        console.error('Error checking readers:', err);
      }
    });
  }

  readCacCard(): void {
    if (!this.selectedReader) return;

    if (this.usePinModal) {
      // Show PIN modal
      this.showPinEntry = true;
    } else {
      // Skip PIN modal, go straight to reading (Windows will prompt for PIN)
      this.readCacCardDirectly();
    }
  }

  readCacCardDirectly(pin?: string): void {
    if (!this.selectedReader) return;

    this.isLoading = true;
    this.updateStatus('Reading CAC', 'Accessing CAC card. Windows will prompt for PIN...');

    // Use regular HTTP POST - form submission in iframe doesn't trigger Windows PIN dialog properly
    // The PIN dialog is triggered by backend when accessing certificate private key
    this.cacReaderService.readCacCertificate(this.selectedReader, pin).subscribe({
      next: (cert) => {
        this.currentCertificate = cert;
        this.displayCertificateInfo(cert);
        this.updateStatus('CAC Read Successfully', `Certificate loaded: ${cert.subject}`);
        this.loadRevocationDistributionPoints();
        this.isLoading = false;
      },
      error: (err) => {
        const errorMsg = err.error?.error || err.error?.details || err.message || 'Failed to read CAC certificate';

        // Check if it's an access/authentication error
        if (errorMsg.toLowerCase().includes('access') ||
          errorMsg.toLowerCase().includes('pin') ||
          errorMsg.toLowerCase().includes('unauthorized') ||
          errorMsg.toLowerCase().includes('denied')) {
          this.updateStatus('Access Denied', 'Unable to access certificate. PIN may be incorrect or Windows PIN prompt was cancelled. Please try again.');
        } else {
          this.currentCertificate = null;
          this.certificateInfo = '';
          this.updateStatus('Failed to Read CAC', errorMsg);
        }
        this.isLoading = false;
        console.error(err);
      }
    });
  }

  onPinSubmitted(pin: string): void {
    this.showPinEntry = false;
    this.readCacCardDirectly(pin);
  }

  onPinCancelled(): void {
    this.showPinEntry = false;
  }

  displayCertificateInfo(cert: Certificate): void {
    const isActive = new Date(cert.notBefore) <= new Date() && new Date() <= new Date(cert.notAfter);
    this.certificateInfo = `Subject: ${cert.subject}\n\n` +
      `Issuer: ${cert.issuer}\n\n` +
      `Valid From: ${new Date(cert.notBefore).toLocaleString()}\n\n` +
      `Valid To: ${new Date(cert.notAfter).toLocaleString()}\n\n` +
      `Thumbprint: ${cert.thumbprint}\n\n` +
      `Is Active: ${isActive ? 'Yes ✓' : 'No ✗'}`;
  }

  validateChain(): void {
    if (!this.currentCertificate) return;

    this.isLoading = true;
    this.updateStatus('Validating Chain', 'Checking certificate chain...');

    this.certificateService.validateChain(this.currentCertificate.certificateBase64).subscribe({
      next: (chainInfo) => {
        let result = `Chain Valid: ${chainInfo.isValid ? 'Yes ✓' : 'No ✗'}\n\n`;

        // Show online validation failure notification prominently
        if (chainInfo.onlineValidationFailed && chainInfo.onlineValidationFailureReason) {
          result += `\n${chainInfo.onlineValidationFailureReason}\n\n`;
        }

        // Check for real revocation in chain errors
        const hasRealRevocation = chainInfo.chainErrors.some(error =>
          error.includes('REAL REVOCATION') || error.includes('🚫')
        );
        if (hasRealRevocation) {
          result += `\n🚫 REAL REVOCATION DETECTED 🚫\n`;
          result += `The certificate has been confirmed as REVOKED by both online and offline checks.\n\n`;
        }

        if (chainInfo.chainErrors.length > 0) {
          result += 'Chain Errors:\n';
          chainInfo.chainErrors.forEach(error => {
            result += `  - ${error}\n`;
          });
          result += '\n';
        }

        if (chainInfo.chain.length > 0) {
          result += 'Chain Certificates:\n';
          chainInfo.chain.forEach(cert => {
            result += `\n  Subject: ${cert.subject}\n`;
            result += `  Issuer: ${cert.issuer}\n`;
            result += `  Valid: ${cert.isValid ? 'Yes ✓' : 'No ✗'}\n`;
            result += `  Thumbprint: ${cert.thumbprint}\n`;
          });
        }

        this.chainInfo = result;
        // Determine status message based on validation result
        let statusMessage: string;
        if (hasRealRevocation) {
          statusMessage = 'Certificate REVOKED - Real revocation detected';
        } else if (chainInfo.onlineValidationFailed) {
          statusMessage = 'Certificate chain validated (offline) - connectivity issue with OCSP/CRL';
        } else {
          statusMessage = chainInfo.isValid ? 'Certificate chain validated successfully' : 'Certificate chain validation failed';
        }
        this.updateStatus(
          chainInfo.isValid ? 'Chain Valid' : 'Chain Invalid',
          statusMessage
        );
        this.isLoading = false;
      },
      error: (err) => {
        this.updateStatus('Error', 'Failed to validate chain');
        this.isLoading = false;
        console.error(err);
      }
    });
  }

  validateOnline(): void {
    if (!this.currentCertificate) return;

    this.isLoading = true;
    this.updateStatus('Validating Online', 'Checking CAC validity for GOVT/Military/Contractors...');

    this.cacValidationService.validateOnline(this.currentCertificate.certificateBase64).subscribe({
      next: (result) => {
        let output = `Status: ${result.status}\n\n`;

        // Show online validation failure notification prominently
        if (result.onlineValidationFailed && result.onlineValidationFailureReason) {
          output += `\n${result.onlineValidationFailureReason}\n\n`;
        }

        output += `Category: ${result.category}\n\n`;
        output += `Is Valid: ${result.isValid ? 'Yes ✓' : 'No ✗'}\n\n`;
        output += `Validated: ${new Date(result.validationTime).toLocaleString()}\n\n`;

        if (result.details.length > 0) {
          output += 'Details:\n';
          result.details.forEach(detail => {
            output += `  - ${detail}\n`;
          });
        }

        this.validationResult = output;
        // Determine status message based on validation result
        let statusMessage: string;
        if (result.onlineValidationFailed && result.onlineValidationFailureReason) {
          if (result.onlineValidationFailureReason.includes('CONNECTIVITY ISSUE')) {
            statusMessage = `Valid ${result.category} CAC (offline) - connectivity issue with OCSP/CRL`;
          } else {
            statusMessage = `Valid ${result.category} CAC (offline) - online validation failed`;
          }
        } else {
          statusMessage = result.isValid ? `Valid ${result.category} CAC` : result.status;
        }
        this.updateStatus(
          result.isValid ? 'Validation Successful' : 'Validation Failed',
          statusMessage
        );
        this.isLoading = false;
      },
      error: (err) => {
        this.updateStatus('Error', 'Failed to validate online');
        this.isLoading = false;
        console.error(err);
      }
    });
  }

  storeCertificate(): void {
    if (!this.currentCertificate) return;

    this.isLoading = true;
    this.updateStatus('Storing Certificate', 'Saving certificate to storage...');

    this.certificateStorageService.storeCertificate(this.currentCertificate.certificateBase64).subscribe({
      next: () => {
        this.updateStatus('Certificate Stored', 'Certificate saved successfully');
        this.loadStoredCertificates();
        this.isLoading = false;
      },
      error: (err) => {
        this.updateStatus('Storage Failed', 'Failed to store certificate');
        this.isLoading = false;
        console.error(err);
      }
    });
  }

  loadStoredCertificates(): void {
    this.certificateStorageService.getStoredCertificates().subscribe({
      next: (certs) => {
        this.storedCertificates = certs;
      },
      error: (err) => {
        console.error(err);
      }
    });
  }

  deleteStoredCertificate(): void {
    if (this.selectedStoredIndex === null || this.selectedStoredIndex < 0 ||
      this.selectedStoredIndex >= this.storedCertificates.length) return;

    const cert = this.storedCertificates[this.selectedStoredIndex];
    this.isLoading = true;

    this.certificateStorageService.deleteCertificate(cert.thumbprint).subscribe({
      next: () => {
        this.updateStatus('Certificate Deleted', 'Certificate removed from storage');
        this.loadStoredCertificates();
        this.selectedStoredIndex = null;
        this.isLoading = false;
      },
      error: (err) => {
        this.updateStatus('Error', 'Failed to delete certificate');
        this.isLoading = false;
        console.error(err);
      }
    });
  }

  updateStatus(title: string, details: string): void {
    this.statusTitle = title;
    this.statusDetails = details;
  }

  loadRevocationDistributionPoints(): void {
    if (!this.currentCertificate) return;

    this.crlOcspMonitoringService.getRevocationDistributionPoints(this.currentCertificate.certificateBase64).subscribe({
      next: (points) => {
        this.revocationDistributionPoints = points;
      },
      error: (err) => {
        console.error('Error loading revocation distribution points:', err);
      }
    });
  }

  checkCrlOcspStatus(): void {
    if (!this.currentCertificate) return;

    this.isLoading = true;
    this.showCrlOcspMonitoring = true;
    this.updateStatus('Checking CRL/OCSP', 'Monitoring revocation service status...');

    this.crlOcspMonitoringService.checkCertificateRevocationStatus(this.currentCertificate.certificateBase64).subscribe({
      next: (status) => {
        this.crlOcspStatus = status;
        const accessibleCount = status.crlStatuses.filter(s => s.isAccessible).length +
          status.ocspStatuses.filter(s => s.isAccessible).length;
        const totalCount = status.crlStatuses.length + status.ocspStatuses.length;

        this.updateStatus(
          'CRL/OCSP Status Checked',
          `${accessibleCount} of ${totalCount} revocation services accessible`
        );
        this.isLoading = false;
      },
      error: (err) => {
        this.updateStatus('Error', 'Failed to check CRL/OCSP status');
        this.isLoading = false;
        console.error(err);
      }
    });
  }

  formatResponseTime(ms?: number): string {
    if (!ms) return 'N/A';
    if (ms < 1000) return `${Math.round(ms)}ms`;
    return `${(ms / 1000).toFixed(2)}s`;
  }

  formatDate(dateString?: string): string {
    if (!dateString) return 'N/A';
    return new Date(dateString).toLocaleString();
  }

  exportCertificate(format: CertificateExportFormat): void {
    if (!this.currentCertificate) return;

    // PFX requires a password
    if (format === CertificateExportFormat.Pfx) {
      this.pendingExportFormat = format;
      this.showPasswordPrompt = true;
      this.passwordForExport = '';
      return;
    }

    this.performExport(format, undefined);
  }

  onPasswordSubmittedForExport(password: string): void {
    this.showPasswordPrompt = false;
    if (this.pendingExportFormat !== null) {
      this.performExport(this.pendingExportFormat, password);
      this.pendingExportFormat = null;
    }
    this.passwordForExport = '';
  }

  onPasswordCancelledForExport(): void {
    this.showPasswordPrompt = false;
    this.pendingExportFormat = null;
    this.passwordForExport = '';
  }

  private performExport(format: CertificateExportFormat, password?: string): void {
    if (!this.currentCertificate) return;

    this.isLoading = true;
    this.updateStatus('Exporting Certificate', 'Preparing certificate file...');

    this.certificateExportService.exportCertificate(this.currentCertificate.certificateBase64, format, password).subscribe({
      next: (blob) => {
        const extension = format === CertificateExportFormat.Pem ? '.pem' :
          format === CertificateExportFormat.Der ? '.der' : '.pfx';
        const fileName = `certificate_${this.currentCertificate!.thumbprint}${extension}`;
        const url = window.URL.createObjectURL(blob);
        const link = document.createElement('a');
        link.href = url;
        link.download = fileName;
        link.click();
        window.URL.revokeObjectURL(url);
        this.updateStatus('Certificate Exported', `Certificate saved as ${fileName}`);
        this.isLoading = false;
      },
      error: (err) => {
        const errorMsg = err.error?.error || err.error?.details || err.message || 'Failed to export certificate';
        this.updateStatus('Export Failed', errorMsg);
        this.isLoading = false;
        console.error(err);
      }
    });
  }

  onFileSelected(event: Event): void {
    const input = event.target as HTMLInputElement;
    if (input.files && input.files.length > 0) {
      const file = input.files[0];
      const fileName = file.name.toLowerCase();

      // Check if it's a PFX/P12 file that might need a password
      if (fileName.endsWith('.pfx') || fileName.endsWith('.p12')) {
        this.pendingImportFile = file;
        this.showPasswordPromptForImport = true;
        this.passwordForImport = '';
        return;
      }

      this.performImport(file);
    }
    // Reset the input so the same file can be selected again
    if (input) {
      input.value = '';
    }
  }

  onPasswordSubmittedForImport(password: string): void {
    this.showPasswordPromptForImport = false;
    if (this.pendingImportFile) {
      this.performImport(this.pendingImportFile, password);
      this.pendingImportFile = null;
    }
    this.passwordForImport = '';
  }

  onPasswordCancelledForImport(): void {
    this.showPasswordPromptForImport = false;
    this.pendingImportFile = null;
    this.passwordForImport = '';
  }

  private performImport(file: File, password?: string): void {
    this.isLoading = true;
    this.updateStatus('Importing Certificate', 'Reading certificate file...');

    this.certificateExportService.importCertificate(file, password).subscribe({
      next: (cert) => {
        this.currentCertificate = {
          subject: cert.subject,
          issuer: cert.issuer,
          notBefore: cert.notBefore,
          notAfter: cert.notAfter,
          thumbprint: cert.thumbprint,
          serialNumber: cert.serialNumber,
          certificateBase64: cert.certificateBase64
        };
        this.displayCertificateInfo(this.currentCertificate);
        this.updateStatus('Certificate Imported', `Certificate loaded: ${cert.subject}`);
        this.loadRevocationDistributionPoints();
        this.isLoading = false;
      },
      error: (err) => {
        const errorMsg = err.error?.error || err.error?.details || err.message || 'Failed to import certificate';
        this.updateStatus('Import Failed', errorMsg);
        this.isLoading = false;
        console.error(err);
      }
    });
  }

  viewCertificateDetails(): void {
    if (!this.currentCertificate) return;

    this.isLoading = true;
    this.showCertificateDetails = true;
    this.updateStatus('Loading Details', 'Retrieving detailed certificate information...');

    this.certificateService.getCertificateDetails(this.currentCertificate.certificateBase64).subscribe({
      next: (details) => {
        this.certificateDetails = details;
        this.updateStatus('Details Loaded', 'Certificate details retrieved successfully');
        this.isLoading = false;
      },
      error: (err) => {
        this.updateStatus('Error', 'Failed to load certificate details');
        this.isLoading = false;
        console.error(err);
      }
    });
  }

  loadExpiringCertificates(): void {
    this.isLoading = true;
    this.showExpiringCertificates = true;
    this.updateStatus('Loading Expiring Certificates', 'Checking for certificates expiring soon...');

    this.certificateStorageService.getExpiringCertificates(90).subscribe({
      next: (certs) => {
        this.expiringCertificates = certs;
        this.updateStatus('Expiring Certificates Loaded', `Found ${certs.length} certificate(s) expiring within 90 days`);
        this.isLoading = false;
      },
      error: (err) => {
        this.updateStatus('Error', 'Failed to load expiring certificates');
        this.isLoading = false;
        console.error(err);
      }
    });
  }

  searchCertificates(): void {
    this.isLoading = true;
    this.updateStatus('Searching', 'Filtering certificates...');

    this.certificateStorageService.searchCertificates(this.searchCriteria).subscribe({
      next: (certs) => {
        this.storedCertificates = certs;
        this.updateStatus('Search Complete', `Found ${certs.length} matching certificate(s)`);
        this.isLoading = false;
      },
      error: (err) => {
        this.updateStatus('Error', 'Failed to search certificates');
        this.isLoading = false;
        console.error(err);
      }
    });
  }

  clearSearch(): void {
    this.searchCriteria = {};
    this.loadStoredCertificates();
  }

  toggleSearchFilters(): void {
    this.showSearchFilters = !this.showSearchFilters;
  }

  getObjectKeys(obj: { [key: string]: string }): string[] {
    return Object.keys(obj);
  }
}

