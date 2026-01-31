import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable } from 'rxjs';

@Injectable({ providedIn: 'root' })
export class EnrollService {
  constructor(private http: HttpClient) {}

  enroll(csr: ArrayBuffer): Observable<Blob> {
    return this.http.post('/.well-known/est/simpleenroll', csr, {
      responseType: 'blob',
      headers: { 'Content-Type': 'application/pkcs10', 'Accept': 'application/pkix-cert' }
    });
  }
}
