import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable } from 'rxjs';
import { CertificateDetails } from './certificate-export.service';

export interface CertificateChainInfo {
  isValid: boolean;
  chainErrors: string[];
  chain: CertificateInfo[];
  onlineValidationFailed?: boolean;
  onlineValidationFailureReason?: string;
}

export interface CertificateInfo {
  subject: string;
  issuer: string;
  notBefore: string;
  notAfter: string;
  isValid: boolean;
  thumbprint: string;
}

@Injectable({
  providedIn: 'root'
})
export class CertificateService {
  private apiUrl = '/api/certificate';

  constructor(private http: HttpClient) { }

  validateChain(certificateBase64: string): Observable<CertificateChainInfo> {
    return this.http.post<CertificateChainInfo>(`${this.apiUrl}/validate-chain`, {
      certificateBase64
    });
  }

  isCertificateActive(certificateBase64: string): Observable<{ isActive: boolean }> {
    return this.http.post<{ isActive: boolean }>(`${this.apiUrl}/is-active`, {
      certificateBase64
    });
  }

  getCertificateDetails(certificateBase64: string): Observable<CertificateDetails> {
    return this.http.post<CertificateDetails>(`${this.apiUrl}/details`, {
      certificateBase64
    });
  }
}

