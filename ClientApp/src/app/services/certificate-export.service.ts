import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable } from 'rxjs';

export enum CertificateExportFormat {
  Pem = 0,
  Der = 1,
  Pfx = 2
}

export interface CertificateDetails {
  subject: string;
  issuer: string;
  serialNumber: string;
  thumbprint: string;
  notBefore: string;
  notAfter: string;
  version: string;
  signatureAlgorithm: string;
  publicKeyAlgorithm: string;
  keySize: number;
  hasPrivateKey: boolean;
  keyUsage: string[];
  extendedKeyUsage: string[];
  subjectAlternativeNames: string[];
  certificatePolicies: string[];
  crlDistributionPoints: string[];
  ocspUrls: string[];
  subjectNameParts: { [key: string]: string };
  issuerNameParts: { [key: string]: string };
  daysUntilExpiration: number;
  isExpiringSoon: boolean;
}

@Injectable({
  providedIn: 'root'
})
export class CertificateExportService {
  private apiUrl = '/api/certificateexport';

  constructor(private http: HttpClient) { }

  exportCertificate(certificateBase64: string, format: CertificateExportFormat, password?: string): Observable<Blob> {
    const body: any = {
      certificateBase64,
      format
    };
    if (password) {
      body.password = password;
    }
    return this.http.post(`${this.apiUrl}/export`, body, { responseType: 'blob' });
  }

  importCertificate(file: File, password?: string): Observable<any> {
    const formData = new FormData();
    formData.append('file', file);
    if (password) {
      formData.append('password', password);
    }
    return this.http.post(`${this.apiUrl}/import`, formData);
  }
}

