import { Component } from '@angular/core';
import { Router } from '@angular/router';

import { AccountService } from '../_services';

@Component({ selector: 'app-layout', templateUrl: './layout.component.html' })
export class LayoutComponent {
  constructor(
    private router: Router,
    private accountService: AccountService
  ) {
    if (this.accountService.accountValue) {
      this.router.navigate(['/']);
    }
  }
}