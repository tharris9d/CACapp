import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable } from 'rxjs';

export interface ValidationResult {
  isValid: boolean;
  status: string;
  category: string;
  details: string[];
  validationTime: string;
  onlineValidationFailed?: boolean;
  onlineValidationFailureReason?: string;
}

@Injectable({
  providedIn: 'root'
})
export class CacValidationService {
  private apiUrl = '/api/cacvalidation';

  constructor(private http: HttpClient) { }

  validateOnline(certificateBase64: string): Observable<ValidationResult> {
    return this.http.post<ValidationResult>(`${this.apiUrl}/validate-online`, {
      certificateBase64
    });
  }
}

