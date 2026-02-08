import { Component, OnInit } from '@angular/core';
import { DomSanitizer, SafeHtml } from '@angular/platform-browser';
import { DocumentService } from '../../services/document.service';

@Component({
    selector: 'app-certification-practice-statement',
    templateUrl: './certification-practice-statement.component.html',
    styleUrls: ['./certification-practice-statement.component.scss'],
    standalone: false
})
export class CertificationPracticeStatementComponent implements OnInit {
  htmlContent: SafeHtml = '';
  loading: boolean = true;
  error: string | null = null;

  constructor(
    private documentService: DocumentService,
    private sanitizer: DomSanitizer
  ) {}

  ngOnInit(): void {
    this.loadDocument();
  }

  loadDocument(): void {
    this.loading = true;
    this.error = null;

    this.documentService.getCertificationPracticeStatement().subscribe({
      next: (markdown) => {
        this.htmlContent = this.sanitizer.bypassSecurityTrustHtml(
          this.markdownToHtml(markdown)
        );
        this.loading = false;
      },
      error: (err) => {
        console.error('Error loading CPS:', err);
        this.error = 'Failed to load the certification practice statement document. Please try again later.';
        this.loading = false;
      }
    });
  }

  private markdownToHtml(markdown: string): string {
    // Basic markdown to HTML conversion
    let html = markdown;

    // Headers
    html = html.replace(/^### (.*$)/gim, '<h3>$1</h3>');
    html = html.replace(/^## (.*$)/gim, '<h2>$1</h2>');
    html = html.replace(/^# (.*$)/gim, '<h1>$1</h1>');

    // Bold
    html = html.replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>');

    // Italic
    html = html.replace(/\*(.*?)\*/g, '<em>$1</em>');

    // Lists
    html = html.replace(/^\- (.*$)/gim, '<li>$1</li>');
    html = html.replace(/(<li>.*<\/li>)/s, '<ul>$1</ul>');

    // Paragraphs
    html = html.split('\n\n').map(para => {
      if (!para.trim().startsWith('<') && para.trim().length > 0) {
        return `<p>${para}</p>`;
      }
      return para;
    }).join('\n');

    // Line breaks
    html = html.replace(/\n/g, '<br>');

    return html;
  }
}
