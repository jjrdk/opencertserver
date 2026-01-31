import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable } from 'rxjs';

@Injectable({ providedIn: 'root' })
export class CsrAttributesService {
  constructor(private http: HttpClient) {}

  getCsrAttributes(): Observable<ArrayBuffer> {
    return this.http.get('/.well-known/est/csrattrs', {
      responseType: 'arraybuffer',
      headers: { 'Accept': 'application/csrattrs' }
    });
  }
}
