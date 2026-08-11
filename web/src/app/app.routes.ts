import { Routes } from '@angular/router';
import { authGuard } from './core/auth.guard';

export const routes: Routes = [
  {
    path: 'maker',
    loadComponent: () =>
      import('./features/maker-portal/maker-portal.component').then(
        (m) => m.MakerPortalComponent,
      ),
    canActivate: [authGuard],
  },
  {
    path: 'checker',
    loadComponent: () =>
      import('./features/checker-dashboard/checker-dashboard.component').then(
        (m) => m.CheckerDashboardComponent,
      ),
    canActivate: [authGuard],
  },
  {
    path: 'login',
    loadComponent: () =>
      import('./features/login/login.component').then((m) => m.LoginComponent),
  },
  { path: '', redirectTo: 'maker', pathMatch: 'full' },
  { path: '**', redirectTo: 'maker' },
];
