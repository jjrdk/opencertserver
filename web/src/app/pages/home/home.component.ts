import { Component } from '@angular/core';

@Component({
  selector: 'app-home',
  templateUrl: './home.component.html',
  styleUrls: ['./home.component.scss']
})
export class HomeComponent {
  openGitHub(): void {
    window.open('https://github.com/jjrdk/opencertserver', '_blank', 'noopener,noreferrer');
  }
}
