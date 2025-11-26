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
    // Note: Windows PIN dialog is triggered by backend when accessing certificate private key.
    // The HTTP method (XHR vs form) doesn't affect PIN dialog positioning, which is a Windows security restriction.
    // However, if full browser navigation is required, use readCacCertificateViaForm() instead.
    return this.http.post<Certificate>(`${this.apiUrl}/read`, { readerName, pin });
  }

  /**
   * Alternative method using form submission for full browser navigation context.
   * This may help with Windows PIN dialog association, though positioning is still restricted by Windows security.
   */
  readCacCertificateViaForm(readerName: string | null, pin?: string): Observable<Certificate> {
    return new Observable(observer => {
      // Create a hidden iframe for form submission (preserves SPA state)
      const iframe = document.createElement('iframe');
      iframe.style.display = 'none';
      iframe.name = 'cac-read-iframe-' + Date.now();
      document.body.appendChild(iframe);

      // Create form with proper encoding
      const form = document.createElement('form');
      form.method = 'POST';
      form.action = `${this.apiUrl}/read`;
      form.target = iframe.name;
      form.enctype = 'application/x-www-form-urlencoded';
      form.style.display = 'none';
      
      // Add form fields
      const readerInput = document.createElement('input');
      readerInput.type = 'hidden';
      readerInput.name = 'readerName';
      readerInput.value = readerName || '';
      form.appendChild(readerInput);
      
      if (pin) {
        const pinInput = document.createElement('input');
        pinInput.type = 'hidden';
        pinInput.name = 'pin';
        pinInput.value = pin;
        form.appendChild(pinInput);
      }
      
      // Handle iframe response
      let responseReceived = false;
      iframe.onload = () => {
        if (responseReceived) return;
        responseReceived = true;
        
        try {
          const iframeDoc = iframe.contentDocument || (iframe.contentWindow as any)?.document;
          if (iframeDoc?.body) {
            const responseText = iframeDoc.body.textContent || iframeDoc.body.innerText;
            if (responseText) {
              try {
                const result = JSON.parse(responseText);
                observer.next(result);
                observer.complete();
              } catch (e) {
                // Fallback to regular HTTP on parse error
                this.http.post<Certificate>(`${this.apiUrl}/read`, { readerName, pin }).subscribe({
                  next: (cert) => observer.next(cert),
                  error: (err) => observer.error(err),
                  complete: () => observer.complete()
                });
              }
            }
          }
        } catch (e) {
          // Cross-origin error - fallback to regular HTTP
          this.http.post<Certificate>(`${this.apiUrl}/read`, { readerName, pin }).subscribe({
            next: (cert) => observer.next(cert),
            error: (err) => observer.error(err),
            complete: () => observer.complete()
          });
        } finally {
          // Clean up after a delay
          setTimeout(() => {
            if (document.body.contains(iframe)) document.body.removeChild(iframe);
            if (document.body.contains(form)) document.body.removeChild(form);
          }, 1000);
        }
      };
      
      // Submit form
      document.body.appendChild(form);
      form.submit();
    });
  }

  isReaderAvailable(): Observable<{ available: boolean }> {
    return this.http.get<{ available: boolean }>(`${this.apiUrl}/available`);
  }
}

