import { Injectable } from '@angular/core';
import { Router, ActivatedRouteSnapshot, RouterStateSnapshot } from '@angular/router';

import { AccountService } from '../_services';

@Injectable({ providedIn: 'root' })
export class AuthGuard {
    constructor(
        private router: Router,
        private accountService: AccountService
    ) { }

    canActivate(route: ActivatedRouteSnapshot, state: RouterStateSnapshot) {
        const account = this.accountService.accountValue;
        if (!account) {
            this.router.navigate(['/account/login']);
            return false;
        }
        // Check for admin role
        if (account.role !== 'Admin' && state.url.includes('/admin')) {
            this.router.navigate(['/']);
            return false;
        }
        return true;
    }
}
