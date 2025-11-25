import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable } from 'rxjs';

export interface StoredCertificate {
  thumbprint: string;
  subject: string;
  issuer: string;
  notBefore: string;
  notAfter: string;
  storedDate: string;
  isActive: boolean;
  daysUntilExpiration?: number;
}

export interface CertificateSearchCriteria {
  searchText?: string;
  category?: string;
  isActive?: boolean;
  expiresBefore?: string;
  expiresAfter?: string;
  daysUntilExpiration?: number;
  expiringSoon?: boolean;
}

@Injectable({
  providedIn: 'root'
})
export class CertificateStorageService {
  private apiUrl = '/api/certificatestorage';

  constructor(private http: HttpClient) { }

  storeCertificate(certificateBase64: string): Observable<{ message: string }> {
    return this.http.post<{ message: string }>(`${this.apiUrl}/store`, {
      certificateBase64
    });
  }

  getStoredCertificates(): Observable<StoredCertificate[]> {
    return this.http.get<StoredCertificate[]>(`${this.apiUrl}/stored`);
  }

  deleteCertificate(thumbprint: string): Observable<{ message: string }> {
    return this.http.delete<{ message: string }>(`${this.apiUrl}/${thumbprint}`);
  }

  searchCertificates(criteria: CertificateSearchCriteria): Observable<StoredCertificate[]> {
    return this.http.post<StoredCertificate[]>(`${this.apiUrl}/search`, criteria);
  }

  getExpiringCertificates(daysThreshold: number = 90): Observable<StoredCertificate[]> {
    return this.http.get<StoredCertificate[]>(`${this.apiUrl}/expiring?daysThreshold=${daysThreshold}`);
  }
}

