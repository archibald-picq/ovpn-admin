import {Component} from "@angular/core";
import {NgbActiveModal} from "@ng-bootstrap/ng-bootstrap";
import { User } from "../models/openvpn-config.model";
import { OpenvpnService } from '../services/openvpn.service';

export class DeleteClientOptions {
    constructor(public readonly user: User) {
    }
}

@Component({
    selector: 'bus-openvpn-confirm-delete-admin-account',
    templateUrl: './confirm-delete-admin-account.component.html',
    styleUrls: ['./confirm-delete-admin-account.component.scss'],
})
export class ConfirmDeleteAdminAccountComponent {
    constructor(
        private readonly openvpnService: OpenvpnService,
        public readonly modal: NgbActiveModal,
        public readonly options: DeleteClientOptions,
    ) {

    }

    public async save(): Promise<void> {
        try {
            await this.openvpnService.deleteAdminAccount(this.options.user);
            this.modal.close('Save click');
        } catch (e) {
            console.warn('service call failed');
        }
    }
}