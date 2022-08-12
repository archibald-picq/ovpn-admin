import {Component} from "@angular/core";
import {NgbActiveModal} from "@ng-bootstrap/ng-bootstrap";
import { IClientCertificate } from '../models/client-certificate.interface';
import { OpenvpnService } from '../services/openvpn.service';

export class DeleteClientOptions {
    constructor(public readonly client: IClientCertificate) {
    }
}

@Component({
    selector: 'bus-openvpn-confirm-delete-client-certificate',
    templateUrl: './confirm-delete-client-certificate.component.html',
    styleUrls: ['./confirm-delete-client-certificate.component.scss'],
})
export class ConfirmDeleteClientCertificateComponent {
    constructor(
        private readonly openvpnService: OpenvpnService,
        public readonly modal: NgbActiveModal,
        public readonly options: DeleteClientOptions,
    ) {

    }

    public async doDeleteCertificate(): Promise<void> {
        try {
            await this.openvpnService.deleteCertificate(this.options.client);
            this.options.client.accountStatus = 'Revoked';
            this.options.client.revocationDate = new Date();
            this.modal.close('Save click');
        } catch (e) {
            console.warn('service call failed');
        }
    }
}