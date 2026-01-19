import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable } from 'rxjs';

@Injectable({
  providedIn: 'root'
})
export class DocumentService {
  constructor(private http: HttpClient) {}

  getCertificatePolicy(): Observable<string> {
    return this.http.get('/assets/docs/opencertserver_cp.md', { responseType: 'text' });
  }

  getCertificationPracticeStatement(): Observable<string> {
    return this.http.get('/assets/docs/opencertserver_cps.md', { responseType: 'text' });
  }
}
