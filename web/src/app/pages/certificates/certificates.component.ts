import { Component, OnInit, ViewChild } from '@angular/core';
import { MatTableDataSource } from '@angular/material/table';
import { MatPaginator } from '@angular/material/paginator';
import { MatSort } from '@angular/material/sort';
import { Certificate } from '../../models/certificate.model';
import { CertificateService } from '../../services/certificate.service';

@Component({
  selector: 'app-certificates',
  templateUrl: './certificates.component.html',
  styleUrls: ['./certificates.component.scss']
})
export class CertificatesComponent implements OnInit {
  displayedColumns: string[] = ['serialNumber', 'subject', 'issuer', 'notBefore', 'notAfter', 'status'];
  dataSource: MatTableDataSource<Certificate>;
  
  @ViewChild(MatPaginator) paginator!: MatPaginator;
  @ViewChild(MatSort) sort!: MatSort;

  certificates: Certificate[] = [];
  searchText: string = '';
  statusFilter: string = 'All';
  loading: boolean = true;
  error: string | null = null;

  constructor(private certificateService: CertificateService) {
    this.dataSource = new MatTableDataSource<Certificate>([]);
  }

  ngOnInit(): void {
    this.loadCertificates();
  }

  loadCertificates(): void {
    this.loading = true;
    this.certificateService.getCertificates().subscribe({
      next: (data) => {
        // Transform API data if needed
        this.certificates = data.map((cert: any) => ({
          id: cert.id || cert.serialNumber,
          serialNumber: cert.serialNumber || '',
          subject: cert.subject || cert.subjectName || '',
          issuer: cert.issuer || cert.issuerName || '',
          notBefore: cert.notBefore || cert.validFrom || '',
          notAfter: cert.notAfter || cert.validTo || '',
          status: this.determineStatus(cert),
          thumbprint: cert.thumbprint || cert.fingerprint || ''
        }));
        
        this.dataSource.data = this.certificates;
        this.dataSource.paginator = this.paginator;
        this.dataSource.sort = this.sort;
        this.applyFilter();
        this.loading = false;
        this.error = null;
      },
      error: (err) => {
        console.error('Error loading certificates:', err);
        this.error = 'Failed to load certificates. Please try again later.';
        this.loading = false;
      }
    });
  }

  determineStatus(cert: any): 'Valid' | 'Expired' | 'Revoked' {
    if (cert.status === 'Revoked' || cert.revoked) return 'Revoked';
    const now = new Date();
    const notAfter = new Date(cert.notAfter || cert.validTo);
    if (notAfter < now) return 'Expired';
    return 'Valid';
  }

  applyFilter(): void {
    let filtered = this.certificates;

    // Apply search filter
    if (this.searchText) {
      const searchLower = this.searchText.toLowerCase();
      filtered = filtered.filter(cert =>
        cert.subject.toLowerCase().includes(searchLower) ||
        cert.serialNumber.toLowerCase().includes(searchLower) ||
        cert.issuer.toLowerCase().includes(searchLower)
      );
    }

    // Apply status filter
    if (this.statusFilter !== 'All') {
      filtered = filtered.filter(cert => cert.status === this.statusFilter);
    }

    this.dataSource.data = filtered;
  }
}
