import { Component, OnInit } from '@angular/core';
import { first } from 'rxjs/operators';
import { AccountService } from '../../_services';
import { Account } from '../../_models';

@Component({ templateUrl: 'list.component.html' })
export class ListComponent implements OnInit {
  accounts!: any[];

  constructor(private accountService: AccountService) {}

  ngOnInit() {
    this.accountService
      .getAll()
      .pipe(first())
      .subscribe((accounts) => (this.accounts = accounts));
  }

  deleteAccount(id: string) {
    const account = this.accounts.find((x) => x.id === id);

    // Check if the account role is Admin or User - if so, don't allow deletion
    if (account.role === 'Admin' || account.role === 'User') {
      return;
    }

    account.isDeleting = true;
    this.accountService
      .delete(id)
      .pipe(first())
      .subscribe(
        () => (this.accounts = this.accounts.filter((x) => x.id !== id))
      );
  }

  // Helper method to determine if delete button should be shown
  canDeleteAccount(account: any): boolean {
    return account.role !== 'Admin' && account.role !== 'User';
  }
}
