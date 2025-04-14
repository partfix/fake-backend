import { Component, OnInit } from '@angular/core';
import { first } from 'rxjs/operators';
import { AccountService } from '../../_services';
import { Account } from '../../_models';

@Component({ templateUrl: 'list.component.html' })
export class ListComponent implements OnInit {
  accounts!: any[];

  constructor(private accountService: AccountService) {}

  ngOnInit() {
    this.loadAccounts();
  }

  private loadAccounts() {
    this.accountService
      .getAll()
      .pipe(first())
      .subscribe((accounts) => (this.accounts = accounts));
  }

  deleteAccount(id: string) {
    const account = this.accounts.find((x) => x.id === id);

    account.isDeleting = true;
    this.accountService
      .delete(id)
      .pipe(first())
      .subscribe(
        () => (this.accounts = this.accounts.filter((x) => x.id !== id))
      );
  }

  toggleAccountStatus(account: any) {
    account.isToggling = true;
    const newStatus = !account.isActive;

    this.accountService
      .updateStatus(account.id, newStatus)
      .pipe(first())
      .subscribe({
        next: () => {
          account.isActive = newStatus;
          account.isToggling = false;
        },
        error: error => {
          console.error('Error updating account status:', error);
          account.isToggling = false;
        }
      });
  }
}
