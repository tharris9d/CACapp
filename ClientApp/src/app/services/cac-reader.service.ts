import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable } from 'rxjs';

export interface Certificate {
  subject: string;
  issuer: string;
  notBefore: string;
  notAfter: string;
  thumbprint: string;
  serialNumber: string;
  certificateBase64: string;
}

@Injectable({
  providedIn: 'root'
})
export class CacReaderService {
  // Use relative URL when using proxy, or full URL if proxy not configured
  private apiUrl = '/api/cacreader';

  constructor(private http: HttpClient) { }

  getAvailableReaders(): Observable<{ readers: string[], count: number, message?: string, error?: string }> {
    return this.http.get<{ readers: string[], count: number, message?: string, error?: string }>(`${this.apiUrl}/readers`);
  }

  readCacCertificate(readerName: string | null, pin?: string): Observable<Certificate> {
    return this.http.post<Certificate>(`${this.apiUrl}/read`, { readerName, pin });
  }

  isReaderAvailable(): Observable<{ available: boolean }> {
    return this.http.get<{ available: boolean }>(`${this.apiUrl}/available`);
  }
}

