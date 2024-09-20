import {AccountEditDTO} from '../../models/account-edit.model';
import {OpenvpnConfig, User} from '../../models/openvpn-config.model';
import {AccountService} from '../../services/account.service';
import {ActivatedRoute, Router} from '@angular/router';
import {Component} from '@angular/core';

@Component({
  selector: 'bus-openvpn-setup-account',
  templateUrl: './create-account.component.html',
  styleUrls: ['./create-account.component.scss'],
})
export class CreateAccountComponent {
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
      this.loading = true;
      await this.accountService.createAdminAccount(this.account);
      this.config.unconfigured = false;
      this.config.preferences!.users.push(new User(
        this.account.username,
        this.account.name,
      ));
      await this.router.navigate(['../create-server'], {relativeTo: this.activatedRoute /* , skipLocationChange: true */ });
    } catch (e: any) {
      this.loading = false;
      console.warn('error', e);
      this.error = e.message;
    }
  }
}
