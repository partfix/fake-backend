import { Component } from '@angular/core';
import { AccountService } from '../_services';

@Component({ templateUrl: 'home.component.html' })
export class HomeComponent {
    account: any;

    constructor(private accountService: AccountService) { 
        // Ensure account has a fallback if it's undefined or null
        this.account = this.accountService.accountValue || { firstName: 'Guest' };
    }
}
