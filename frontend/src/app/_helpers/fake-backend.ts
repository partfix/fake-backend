import { Injectable } from '@angular/core';
import {
  HttpRequest,
  HttpResponse,
  HttpHandler,
  HttpEvent,
  HttpInterceptor,
  HTTP_INTERCEPTORS,
  HttpHeaders,
} from '@angular/common/http';
import { Observable, of, throwError } from 'rxjs';
import { delay, materialize, dematerialize } from 'rxjs/operators';

import { AlertService } from '../_services';
import { Account, Role } from '../_models';

// array in local storage for accounts
const accountsKey = 'angular-10-signup-verification-boilerplate-accounts';
let accounts = JSON.parse(localStorage.getItem(accountsKey) ?? '[]');

@Injectable()
export class FakeBackendInterceptor implements HttpInterceptor {
  constructor(private alertService: AlertService) {}

  intercept(
    request: HttpRequest<any>,
    next: HttpHandler
  ): Observable<HttpEvent<any>> {
    const { url, method, headers, body } = request;
    const alertService = this.alertService;

    return handleRoute();

    function handleRoute() {
      switch (true) {
        case url.endsWith('/accounts/authenticate') && method === 'POST':
          return authenticate();
        case url.endsWith('/accounts/refresh-token') && method === 'POST':
          return refreshToken();
        case url.endsWith('/accounts/revoke-token') && method === 'POST':
          return revokeToken();
        case url.endsWith('/accounts/register') && method === 'POST':
          return register();
        case url.endsWith('/accounts/verify-email') && method === 'POST':
          return verifyEmail();
        case url.endsWith('/accounts/forgot-password') && method === 'POST':
          return forgotPassword();
        case url.endsWith('/accounts/validate-reset-token') &&
          method === 'POST':
          return validateResetToken(body);
        case url.endsWith('/accounts/reset-password') && method === 'POST':
          return resetPassword();
        case url.endsWith('/accounts') && method === 'GET':
          return getAccounts();
        case url.match(/\/accounts\/\d+$/) && method === 'GET':
          return getAccountById();
        case url.endsWith('/accounts') && method === 'POST':
          return createAccount();
        case url.match(/\/accounts\/\d+$/) && method === 'PUT':
          return updateAccount();
        case url.match(/\/accounts\/\d+$/) && method === 'DELETE':
          return deleteAccount();
        case url.match(/\/accounts\/\d+\/status$/) && method === 'PATCH':
          return updateAccountStatus();
        default:
          // pass through any requests not handled above
          return next.handle(request);
      }
    }

    // route functions

    function authenticate() {
      const { email, password } = body;
      const account = accounts.find(
        (x: Account) =>
          x.email === email && x.password === password && x.isVerified
      );

      if (!account) return error('Email or password is incorrect');
      if (account.isActive === false) return error('Account is deactivated');

      // add refresh token to account
      account.refreshTokens.push(generateRefreshToken());
      localStorage.setItem(accountsKey, JSON.stringify(accounts));

      return ok({
        ...basicDetails(account),
        jwtToken: generateJwtToken(account),
      });
    }

    function refreshToken() {
      const refreshToken = getRefreshToken();

      if (!refreshToken) return unauthorized();

      const account = accounts.find((x: Account) =>
        x.refreshTokens.includes(refreshToken)
      );

      if (!account) return unauthorized();

      // replace old refresh token with a new one and save
      account.refreshTokens = account.refreshTokens.filter(
        (x: string) => x !== refreshToken
      );
      account.refreshTokens.push(generateRefreshToken());
      localStorage.setItem(accountsKey, JSON.stringify(accounts));

      return ok({
        ...basicDetails(account),
        jwtToken: generateJwtToken(account),
      });
    }

    function revokeToken() {
      if (!isAuthenticated()) return unauthorized();

      const refreshToken = getRefreshToken();
      const account = accounts.find((x: Account) =>
        x.refreshTokens.includes(refreshToken)
      );

      // revoke token and save
      account.refreshTokens = account.refreshTokens.filter(
        (x: string) => x !== refreshToken
      );
      localStorage.setItem(accountsKey, JSON.stringify(accounts));

      return ok();
    }

    function register() {
      const account = body;

      if (accounts.find((x: Account) => x.email === account.email)) {
        //display email already registered "email" in alert
        setTimeout(() => {
          alertService.info(
            `
                    <h4>Already Registered</h4>
                    <p>Your email ${account.email} is already registered.</p>
                    <p>If you don't know your password please visit the <a href="${location.origin}/account/forgot-password">forgot password</a> page.</p>
                    <div><strong>Note:</strong> The fake backend displayed this "email" so you can test without an api. A real backend would send a real email.</div>
                    `,
            { autoClose: false }
          );
        }, 1000);

        // always return ok() response to prevent email enumeration
        return ok();
      }

      //assign acount id and a few other properties then save
      account.id = newAccountId();
      if (account.id === 1) {
        // first registered account is an admin
        account.role = Role.Admin;
      } else {
        account.role = Role.User;
      }
      account.dateCreated = new Date().toISOString();
      account.verificationToken = new Date().getTime().toString();
      account.isVerified = false;
      account.isActive = true; // Set initial active status
      account.refreshTokens = [];
      delete account.confirmpassword;
      accounts.push(account);
      localStorage.setItem(accountsKey, JSON.stringify(accounts));

      // display verification email in alert
      setTimeout(() => {
        const verifyUrl = `${location.origin}/account/verify-email?token=${account.verificationToken}`;
        alertService.info(
          `
                    <h4>Verification Email</h4>
                    <p>Thanks for registering!</p>
                    <p>Please click the link below to verify your email address:</p>
                    <p><a href="${verifyUrl}">${verifyUrl}</a></p>
                    <div><strong>Note:</strong> The fake backend displayed this "email" so you can test without an api. A real backend would send a real email.</div>
                `,
          { autoClose: false }
        );
      }, 1000);

      return ok();
    }

    function verifyEmail() {
      const { token } = body;
      const account = accounts.find(
        (x: Account) => !!x.verificationToken && x.verificationToken === token
      );

      if (!account) return error('Verification failed');

      // set is verified flag to true if token is valid
      account.isVerified = true;
      localStorage.setItem(accountsKey, JSON.stringify(accounts));

      return ok();
    }

    function forgotPassword() {
      const { email } = body;
      const account = accounts.find((x: Account) => x.email === email);

      // always return ok() response to prevent email enumeration
      if (!account) return ok();

      // create reset token that expires after 24 hours
      account.resetToken = new Date().getTime().toString();
      account.resetTokenExpires = new Date(
        Date.now() + 24 * 60 * 60 * 1000
      ).toISOString();
      localStorage.setItem(accountsKey, JSON.stringify(accounts));

      // display password reset email in alert
      setTimeout(() => {
        const resetUrl = `${location.origin}/account/reset-password?token=${account.resetToken}`;
        alertService.info(
          `<h4>Reset Password Email</h4>
            <p>Please click the below link to reset your password, the link will be valid for 1 day:</p>
            <p><a href="${resetUrl}">${resetUrl}</a></p>
            <div><strong>NOTE:</strong> The fake backend displayed this "email" so you can test without an api. A real backend would send a real email.</div>`,
          { autoClose: false }
        );
      }, 1000);

      return ok();
    }

    function validateResetToken(body: { token: string }) {
      const { token } = body;
      const account = accounts.find(
        (x: Account) =>
          !!x.resetToken &&
          x.resetToken === token &&
          x.resetTokenExpires &&
          new Date() < new Date(x.resetTokenExpires)
      );

      if (!account) return error('Invalid token');

      return ok();
    }

    function resetPassword() {
      const { token, password } = body;
      const account = accounts.find(
        (x: Account) =>
          !!x.resetToken &&
          x.resetToken === token &&
          x.resetTokenExpires &&
          new Date() < new Date(x.resetTokenExpires)
      );

      if (!account) return error('Invalid token');

      // update password and remove reset token
      account.password = password;
      account.isVerified = true;
      delete account.resetToken;
      delete account.resetTokenExpires;
      localStorage.setItem(accountsKey, JSON.stringify(accounts));

      return ok();
    }

    function getAccounts() {
      if (!isAuthenticated()) return unauthorized();
      return ok(accounts.map((x: Account) => basicDetails(x)));
    }

    function getAccountById() {
      if (!isAuthenticated()) return unauthorized();

      const id = idFromUrl();

      if (!id) {
        return error('Account ID is required');
      }

      // Use optional chaining and strict type check
      const account = accounts.find((x: Account) => Number(x.id) === id);

      if (!account) return error('Account not found');

      const current = currentAccount();
      if (!current || current.id === undefined) {
        return unauthorized();
      }

      if (account.id !== current.id && !isAuthorized(Role.Admin)) {
        return unauthorized();
      }

      return ok(basicDetails(account));
    }

    function createAccount() {
      if (!isAuthorized(Role.Admin)) return unauthorized();

      const account = body;

      if (accounts.find((x: Account) => x.email === account.email)) {
        return error(`Email ${account.email} is already registered`);
      }

      // assign account id and a few other properties then save
      account.id = newAccountId();
      account.dateCreated = new Date().toISOString();
      account.isVerified = true;
      account.isActive = true; // Set initial active status
      account.refreshTokens = [];
      delete account.confirmPassword;
      accounts.push(account);
      localStorage.setItem(accountsKey, JSON.stringify(accounts));

      return ok();
    }

    function updateAccount() {
      if (!isAuthenticated()) return unauthorized();

      const params = body;
      const id = idFromUrl();

      const account = accounts.find((x: Account) => Number(x.id) === id);

      if (!account) return error('Account not found');

      const current = currentAccount();
      if (!current || !current.id) return unauthorized();

      if (account.id !== current.id && !isAuthorized(Role.Admin)) {
        return unauthorized();
      }

      if (!params.password) {
        delete params.password;
      }

      delete params.confirmPassword;

      Object.assign(account, params);
      localStorage.setItem(accountsKey, JSON.stringify(accounts));

      return ok(basicDetails(account));
    }

    function deleteAccount() {
      if (!isAuthenticated()) return unauthorized();

      const accountId = idFromUrl();
      if (!accountId) return error('Account ID is required');

      const account = accounts.find((x: Account) => Number(x.id) === accountId);
      if (!account) return error('Account not found');

      const current = currentAccount();
      if (!current || !current.id) return unauthorized();

      if (account.id !== current.id && !isAuthorized(Role.Admin)) {
        return unauthorized();
      }

      accounts = accounts.filter((x: Account) => Number(x.id) !== accountId);
      localStorage.setItem(accountsKey, JSON.stringify(accounts));

      return ok();
    }

    function updateAccountStatus() {
      if (!isAuthorized(Role.Admin)) return unauthorized();

      const id = url.split('/')[url.split('/').length - 2];
      const { isActive } = body;

      // Convert id to number for comparison since we store IDs as numbers
      const account = accounts.find(
        (x: Account) => Number(x.id) === Number(id)
      );

      if (!account) return error('Account not found');

      // Update account status
      account.isActive = isActive;
      localStorage.setItem(accountsKey, JSON.stringify(accounts));

      return ok(basicDetails(account));
    }

    function ok(body?: any) {
      return of(new HttpResponse({ status: 200, body })).pipe(delay(500)); // delay observable to simulate server api call
    }

    function error(message: string) {
      return throwError({ error: { message } }).pipe(
        materialize(),
        delay(500),
        dematerialize()
      );
    }

    function unauthorized() {
      return throwError({
        status: 401,
        error: { message: 'Unauthorized' },
      }).pipe(materialize(), delay(500), dematerialize());
    }

    function basicDetails(account: Account) {
      const {
        id,
        title,
        firstName,
        lastName,
        email,
        role,
        dateCreated,
        isVerified,
        isActive,
      } = account;
      return {
        id,
        title,
        firstName,
        lastName,
        email,
        role,
        dateCreated,
        isVerified,
        isActive,
      };
    }

    function isAuthenticated() {
      return !!currentAccount();
    }

    function isAuthorized(role: Role) {
      const account = currentAccount();
      if (!account) return false;
      return account.role === role;
    }

    function idFromUrl() {
      const urlParts = url.split('/');
      return parseInt(urlParts[urlParts.length - 1]);
    }

    function newAccountId() {
      const accounts: Account[] = JSON.parse(
        localStorage.getItem(accountsKey) || '[]'
      );
      return accounts.length
        ? Math.max(
            ...accounts.map((x: Account) => (x.id ? parseInt(String(x.id)) : 0))
          ) + 1
        : 1;
    }

    function currentAccount(): Account | undefined {
      const authHeader = headers.get('Authorization');
      if (!authHeader?.startsWith('Bearer fake-jwt-token')) return undefined;

      try {
        const jwtToken = JSON.parse(atob(authHeader.split('.')[1]));
        const tokenExpired = Date.now() > jwtToken.exp * 1000;
        if (tokenExpired) return undefined;

        const accounts: Account[] = JSON.parse(
          localStorage.getItem(accountsKey) || '[]'
        );
        const account = accounts.find((x: Account) => x.id === jwtToken.id);
        return account;
      } catch (error) {
        console.error('Error decoding JWT:', error);
        return undefined;
      }
    }

    function generateJwtToken(account: any) {
      // create token that expires in 15 minutes
      const tokenPayload = {
        exp: Math.round(new Date(Date.now() + 15 * 60 * 1000).getTime() / 1000),
        id: account.id,
      };

      return `fake-jwt-token.${btoa(JSON.stringify(tokenPayload))}`;
    }

    function generateRefreshToken() {
      const token = new Date().getTime().toString();

      // add token cookie that expires in 7 days
      const expires = new Date(
        Date.now() + 7 * 24 * 60 * 60 * 1000
      ).toUTCString();
      document.cookie = `fakeRefreshToken=${token}; expires=${expires}; path=/`;

      return token;
    }

    // get refresh token from cookie
    function getRefreshToken() {
      return (
        document.cookie
          .split('; ')
          .find((x) => x.includes('fakeRefreshToken')) || ''
      ).split('=')[1];
    }
  }
}

export let fakeBackendProvider = {
  // use fake backend in place of Http service for backend-less development
  provide: HTTP_INTERCEPTORS,
  useClass: FakeBackendInterceptor,
  multi: true,
};

@Injectable()
export class FakeBackendInterceptor implements HttpInterceptor {
  private users = [
    {
      id: 1,
      email: 'admin@example.com',
      password: 'admin',
      role: 'Admin',
      employeeId: 1,
    },
    {
      id: 2,
      email: 'user@example.com',
      password: 'user',
      role: 'User',
      employeeId: 2,
    },
  ];

  private employees = [
    {
      id: 1,
      employeeId: 'EMP001',
      userId: 1,
      position: 'Developer',
      departmentId: 1,
      hireDate: '2025-01-01',
      status: 'Active',
    },
    {
      id: 2,
      employeeId: 'EMP002',
      userId: 2,
      position: 'Designer',
      departmentId: 2,
      hireDate: '2025-02-01',
      status: 'Active',
    },
  ];

  private departments = [
    {
      id: 1,
      name: 'Engineering',
      description: 'Software development team',
      employeeCount: 1,
    },
    {
      id: 2,
      name: 'Marketing',
      description: 'Marketing team',
      employeeCount: 1,
    },
  ];

  private workflows = [
    {
      id: 1,
      employeeId: 1,
      type: 'Onboarding',
      details: { task: 'Setup workstation' },
      status: 'Pending',
    },
  ];

  private requests = [
    {
      id: 1,
      employeeId: 2,
      type: 'Equipment',
      requestItems: [{ name: 'Laptop', quantity: 1 }],
      status: 'Pending',
    },
  ];

  intercept(
    request: HttpRequest<any>,
    next: HttpHandler
  ): Observable<HttpEvent<any>> {
    const { url, method, headers, body } = request;

    return of(null)
      .pipe(mergeMap(() => this.handleRoute(url, method, headers, body)))
      .pipe(materialize())
      .pipe(delay(500))
      .pipe(dematerialize());
  }

  private handleRoute(
    url: string,
    method: string,
    headers: any,
    body: any
  ): Observable<HttpEvent<any>> {
    // Accounts Routes
    if (url.endsWith('/accounts/authenticate') && method === 'POST') {
      const { email, password } = body;
      const user = this.users.find(
        (u) => u.email === email && u.password === password
      );
      if (!user) return throwError(() => new Error('Invalid credentials'));
      return of(
        new HttpResponse({
          status: 200,
          body: { ...user, token: 'fake-jwt-token' },
        })
      );
    }

    if (url.endsWith('/accounts') && method === 'GET') {
      return this.authorize(headers, 'Admin', () =>
        of(new HttpResponse({ status: 200, body: this.users }))
      );
    }

    // Employees Routes
    if (url.endsWith('/employees') && method === 'GET') {
      return this.authorize(headers, null, () =>
        of(new HttpResponse({ status: 200, body: this.employees }))
      );
    }

    if (url.endsWith('/employees') && method === 'POST') {
      return this.authorize(headers, 'Admin', () => {
        const employee = { id: this.employees.length + 1, ...body };
        this.employees.push(employee);
        return of(new HttpResponse({ status: 201, body: employee }));
      });
    }

    if (url.match(/\/employees\/\d+$/) && method === 'GET') {
      const id = parseInt(url.split('/').pop()!);
      const employee = this.employees.find((e) => e.id === id);
      return this.authorize(headers, null, () =>
        employee
          ? of(new HttpResponse({ status: 200, body: employee }))
          : throwError(() => new Error('Employee not found'))
      );
    }

    if (url.match(/\/employees\/\d+$/) && method === 'PUT') {
      return this.authorize(headers, 'Admin', () => {
        const id = parseInt(url.split('/').pop()!);
        const employeeIndex = this.employees.findIndex((e) => e.id === id);
        if (employeeIndex === -1)
          return throwError(() => new Error('Employee not found'));
        this.employees[employeeIndex] = { id, ...body };
        return of(
          new HttpResponse({ status: 200, body: this.employees[employeeIndex] })
        );
      });
    }

    if (url.match(/\/employees\/\d+$/) && method === 'DELETE') {
      return this.authorize(headers, 'Admin', () => {
        const id = parseInt(url.split('/').pop()!);
        this.employees = this.employees.filter((e) => e.id !== id);
        return of(
          new HttpResponse({
            status: 200,
            body: { message: 'Employee deleted' },
          })
        );
      });
    }

    if (url.match(/\/employees\/\d+\/transfer$/) && method === 'POST') {
      return this.authorize(headers, 'Admin', () => {
        const id = parseInt(url.split('/')[url.split('/').length - 2]);
        const employee = this.employees.find((e) => e.id === id);
        if (!employee) return throwError(() => new Error('Employee not found'));
        employee.departmentId = body.departmentId;
        this.workflows.push({
          id: this.workflows.length + 1,
          employeeId: id,
          type: 'Transfer',
          details: body,
          status: 'Pending',
        });
        return of(
          new HttpResponse({
            status: 200,
            body: { message: 'Employee transferred' },
          })
        );
      });
    }

    // Departments Routes
    if (url.endsWith('/departments') && method === 'GET') {
      return this.authorize(headers, null, () =>
        of(new HttpResponse({ status: 200, body: this.departments }))
      );
    }

    if (url.endsWith('/departments') && method === 'POST') {
      return this.authorize(headers, 'Admin', () => {
        const department = {
          id: this.departments.length + 1,
          ...body,
          employeeCount: 0,
        };
        this.departments.push(department);
        return of(new HttpResponse({ status: 201, body: department }));
      });
    }

    if (url.match(/\/departments\/\d+$/) && method === 'PUT') {
      return this.authorize(headers, 'Admin', () => {
        const id = parseInt(url.split('/').pop()!);
        const deptIndex = this.departments.findIndex((d) => d.id === id);
        if (deptIndex === -1)
          return throwError(() => new Error('Department not found'));
        this.departments[deptIndex] = {
          id,
          ...body,
          employeeCount: this.departments[deptIndex].employeeCount,
        };
        return of(
          new HttpResponse({ status: 200, body: this.departments[deptIndex] })
        );
      });
    }

    if (url.match(/\/departments\/\d+$/) && method === 'DELETE') {
      return this.authorize(headers, 'Admin', () => {
        const id = parseInt(url.split('/').pop()!);
        this.departments = this.departments.filter((d) => d.id !== id);
        return of(
          new HttpResponse({
            status: 200,
            body: { message: 'Department deleted' },
          })
        );
      });
    }

    // Workflows Routes
    if (url.match(/\/workflows\/employee\/\d+$/) && method === 'GET') {
      return this.authorize(headers, null, () => {
        const employeeId = parseInt(url.split('/').pop()!);
        const workflows = this.workflows.filter(
          (w) => w.employeeId === employeeId
        );
        return of(new HttpResponse({ status: 200, body: workflows }));
      });
    }

    if (url.endsWith('/workflows') && method === 'POST') {
      return this.authorize(headers, 'Admin', () => {
        const workflow = { id: this.workflows.length + 1, ...body };
        this.workflows.push(workflow);
        return of(new HttpResponse({ status: 201, body: workflow }));
      });
    }

    // Requests Routes
    if (url.endsWith('/requests') && method === 'GET') {
      return this.authorize(headers, 'Admin', () =>
        of(new HttpResponse({ status: 200, body: this.requests }))
      );
    }

    if (url.endsWith('/requests') && method === 'POST') {
      return this.authorize(headers, null, () => {
        const request = {
          id: this.requests.length + 1,
          employeeId: this.getUser(headers).employeeId,
          ...body,
        };
        this.requests.push(request);
        return of(new HttpResponse({ status: 201, body: request }));
      });
    }

    if (url.match(/\/requests\/\d+$/) && method === 'PUT') {
      return this.authorize(headers, 'Admin', () => {
        const id = parseInt(url.split('/').pop()!);
        const reqIndex = this.requests.findIndex((r) => r.id === id);
        if (reqIndex === -1)
          return throwError(() => new Error('Request not found'));
        this.requests[reqIndex] = { id, ...body };
        return of(
          new HttpResponse({ status: 200, body: this.requests[reqIndex] })
        );
      });
    }

    if (url.match(/\/requests\/\d+$/) && method === 'DELETE') {
      return this.authorize(headers, 'Admin', () => {
        const id = parseInt(url.split('/').pop()!);
        this.requests = this.requests.filter((r) => r.id !== id);
        return of(
          new HttpResponse({
            status: 200,
            body: { message: 'Request deleted' },
          })
        );
      });
    }

    return next.handle(request);
  }

  private authorize(
    headers: any,
    requiredRole: string | null,
    success: () => Observable<HttpEvent<any>>
  ): Observable<HttpEvent<any>> {
    const user = this.getUser(headers);
    if (!user) return throwError(() => new Error('Unauthorized'));
    if (requiredRole && user.role !== requiredRole)
      return throwError(() => new Error('Forbidden'));
    return success();
  }

  private getUser(headers: any) {
    const authHeader = headers.get('Authorization');
    if (!authHeader || authHeader !== 'Bearer fake-jwt-token') return null;
    return this.users.find((u) => u.token === 'fake-jwt-token');
  }
}

export const fakeBackendProvider = {
  provide: HTTP_INTERCEPTORS,
  useClass: FakeBackendInterceptor,
  multi: true,
};
