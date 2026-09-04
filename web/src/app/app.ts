import { Component, inject, OnInit } from '@angular/core';
import { Router, RouterLink, RouterLinkActive, RouterOutlet } from '@angular/router';
import { AuthService } from './core/auth.service';

@Component({
  selector: 'app-root',
  imports: [RouterOutlet, RouterLink, RouterLinkActive],
  templateUrl: './app.html',
  styleUrl: './app.scss'
})
export class App implements OnInit {
  protected readonly auth = inject(AuthService);
  private readonly router = inject(Router);

  ngOnInit(): void {
    // Boot-time session restore: validate the stored bearer JWT (TokenStore)
    // via GET /api/me so guarded routes survive full page loads (Task 5.7,
    // token-based since Task 10). The authGuard also awaits this, so it is
    // safe even if a navigation fires before ngOnInit.
    void this.auth.restoreSession();
  }

  logout(): void {
    this.auth.logout().subscribe(() => this.router.navigate(['/login']));
  }
}
