import { Component } from '@angular/core';
import { RouterLink } from '@angular/router';

/**
 * Placeholder for the real login form (Task 2.8). Exists so the authGuard's
 * redirect target resolves today.
 */
@Component({
  selector: 'app-login',
  standalone: true,
  imports: [RouterLink],
  templateUrl: './login.component.html',
  styleUrl: './login.component.scss',
})
export class LoginComponent {}
