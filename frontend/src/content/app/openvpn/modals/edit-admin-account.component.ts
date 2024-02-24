import {Component} from "@angular/core";
import {NgbActiveModal} from "@ng-bootstrap/ng-bootstrap";
import { User } from '../models/openvpn-config.model';
import {AccountService} from '../services/account.service';
import {AccountEditDTO} from '../models/account-edit.model';

export class EditAdminAccountOptions {
    constructor(public readonly user: User) {}
}

@Component({
    selector: 'bus-openvpn-edit-admin-account',
    templateUrl: './edit-admin-account.component.html',
    styleUrls: ['./edit-admin-account.component.scss'],
})
export class EditAdminAccountComponent {
    public account: AccountEditDTO = new AccountEditDTO();
    public passwordConfirm = '';
    public error = '';
    public loading = false;
    public original?: User;

    constructor(
        private readonly accountService: AccountService,
        public readonly modal: NgbActiveModal,
        public readonly options: EditAdminAccountOptions,
    ) {
        this.original = options?.user;
        this.account.username = options?.user.username ?? '';
        this.account.name = options?.user.name ?? '';
    }

    public async save(): Promise<void> {
        if (this.account.password && this.account.password !== this.passwordConfirm) {
            this.error = 'Password does not match';
            return ;
        }
        try {
            this.loading = true;
            this.error = '';

            if (this.original) {
                await this.accountService.updateAdminAccount(this.original.username, this.account);
                this.original.username = this.account.username;
                this.original.name = this.account.name;
                this.modal.close(this.original);
            } else {
                await this.accountService.createAdminAccount(this.account);
                this.modal.close(new User(
                  this.account.username,
                  this.account.name,
                ));
            }
        } catch (e: any) {
            console.warn('service call failed: ', e);
            this.error = e.error.message;
        }
        this.loading = false;
    }
}
