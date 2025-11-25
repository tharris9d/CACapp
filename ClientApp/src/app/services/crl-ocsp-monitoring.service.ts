import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable } from 'rxjs';

export interface CrlOcspStatus {
  isAvailable: boolean;
  crlStatuses: CrlStatus[];
  ocspStatuses: OcspStatus[];
  checkTime: string;
  errorMessage?: string;
}

export interface CrlStatus {
  url: string;
  isAccessible: boolean;
  responseTimeMs?: number;
  lastUpdate?: string;
  nextUpdate?: string;
  revokedCertificateCount?: number;
  errorMessage?: string;
  checkTime: string;
}

export interface OcspStatus {
  url: string;
  isAccessible: boolean;
  responseTimeMs?: number;
  responseStatus?: string;
  isRevoked?: boolean;
  thisUpdate?: string;
  nextUpdate?: string;
  errorMessage?: string;
  checkTime: string;
}

export interface RevocationDistributionPoint {
  type: string;
  url: string;
  description?: string;
}

@Injectable({
  providedIn: 'root'
})
export class CrlOcspMonitoringService {
  private apiUrl = '/api/crlocspmonitoring';

  constructor(private http: HttpClient) { }

  checkCertificateRevocationStatus(certificateBase64: string): Observable<CrlOcspStatus> {
    return this.http.post<CrlOcspStatus>(`${this.apiUrl}/check-certificate`, {
      certificateBase64
    });
  }

  checkCrlStatus(url: string): Observable<CrlStatus> {
    return this.http.post<CrlStatus>(`${this.apiUrl}/check-crl`, { url });
  }

  checkOcspStatus(url: string, certificateBase64: string): Observable<OcspStatus> {
    return this.http.post<OcspStatus>(`${this.apiUrl}/check-ocsp`, {
      url,
      certificateBase64
    });
  }

  getRevocationDistributionPoints(certificateBase64: string): Observable<RevocationDistributionPoint[]> {
    return this.http.post<RevocationDistributionPoint[]>(`${this.apiUrl}/distribution-points`, {
      certificateBase64
    });
  }
}



