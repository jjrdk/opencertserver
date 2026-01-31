import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable } from 'rxjs';

@Injectable({ providedIn: 'root' })
export class ServerKeygenService {
  constructor(private http: HttpClient) {}

  serverKeygen(request: any): Observable<Blob> {
    // The request should be a JSON or form-encoded DN and key type
    return this.http.post('/.well-known/est/serverkeygen', request, {
      responseType: 'blob',
      headers: { 'Content-Type': 'application/json', 'Accept': '*/*' }
    });
  }
}
