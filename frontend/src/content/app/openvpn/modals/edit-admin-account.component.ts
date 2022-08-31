import {Component} from "@angular/core";
import {NgbActiveModal} from "@ng-bootstrap/ng-bootstrap";
import { OpenvpnService } from '../services/openvpn.service';
import { User } from '../models/openvpn-config.model';

export class EditAdminAccountOptions {
    constructor(public readonly user: User) {}
}

@Component({
    selector: 'bus-openvpn-edit-admin-account',
    templateUrl: './edit-admin-account.component.html',
    styleUrls: ['./edit-admin-account.component.scss'],
})
export class EditAdminAccountComponent {
    public username = '';
    public name = '';
    public password = '';
    public passwordConfirm = '';
    public error = '';
    public loading = false;
    public original?: User;

    constructor(
        private readonly openvpnService: OpenvpnService,
        public readonly modal: NgbActiveModal,
        public readonly options: EditAdminAccountOptions,
    ) {
        this.original = options?.user;
        this.username = options?.user.username ?? '';
        this.name = options?.user.name ?? '';
    }

    public async save(): Promise<void> {
        if (this.password && this.password !== this.passwordConfirm) {
            this.error = 'Password does not match';
            return ;
        }
        try {
            this.loading = true;
            this.error = '';
            const params = {
                username: this.username,
                name: this.name,
                password: this.password,
            };
            if (this.original) {
                await this.openvpnService.updateAdminAccount(this.original.username, params);
                this.original.username = params.username;
                this.original.name = params.name;
                this.modal.close(this.original);
            } else {
                await this.openvpnService.createAdminAccount(params);
                this.modal.close(new User(params));
            }
        } catch (e: any) {
            this.error = e.error.message;
            console.warn('service call failed: ', e.error.message);
        }
        this.loading = false;
    }
}