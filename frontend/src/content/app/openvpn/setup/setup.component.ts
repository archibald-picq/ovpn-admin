import {Component} from '@angular/core';
import {AccountService} from '../services/account.service';
import {AccountEditDTO} from '../models/account-edit.model';
import {ActivatedRoute, Router} from '@angular/router';
import {OpenvpnConfig} from '../models/openvpn-config.model';

@Component({
  selector: 'bus-openvpn-setup',
  templateUrl: './setup.component.html',
  styleUrls: ['./setup.component.scss'],
})
export class SetupComponent {
  public loading = false;
  public account: AccountEditDTO = new AccountEditDTO();
  public passwordConfirm = '';
  public error?: string;
  private readonly config: OpenvpnConfig;

  constructor(
    private readonly accountService: AccountService,
    public readonly router: Router,
    public readonly activatedRoute: ActivatedRoute,
  ) {
    console.warn('activatedRoute', this.activatedRoute.snapshot.parent?.data);
    this.config = this.activatedRoute.snapshot.parent!.data.config as OpenvpnConfig;
  }

  public async save() {
    this.error = undefined;
    if (!this.account.username) {
      this.error = 'Username is required';
      return;
    }
    if (!this.account.password) {
      this.error = 'Passwords is required';
      return;
    }
    if (this.account.password !== this.passwordConfirm) {
      this.error = 'Passwords does not match';
      return;
    }
    if (!this.account.name) {
      this.account.name = undefined;
    }
    try {
      const user = await this.accountService.createAdminAccount(this.account);
      this.config.unconfigured = false;
      // console.warn('navigate to ./');
      await this.router.navigate(['/']);
    } catch (e: any) {
      console.warn('error', e);
      this.error = e.message;
    }
  }
}
