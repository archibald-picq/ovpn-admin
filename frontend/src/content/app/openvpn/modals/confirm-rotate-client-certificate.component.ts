import {Component} from "@angular/core";
import {NgbActiveModal} from "@ng-bootstrap/ng-bootstrap";
import { IClientCertificate } from '../models/client-certificate.interface';
import { OpenvpnService } from '../services/openvpn.service';

export class RotateClientOptions {
    constructor(public readonly client: IClientCertificate) {
    }
}

@Component({
    selector: 'bus-openvpn-confirm-rotate-client-certificate',
    templateUrl: './confirm-rotate-client-certificate.component.html',
    styleUrls: ['../openvpn.component.scss'],
})
export class ConfirmRotateClientCertificateComponent {
    constructor(
        private readonly openvpnService: OpenvpnService,
        public readonly modal: NgbActiveModal,
        public readonly options: RotateClientOptions,
    ) {

    }

    public async save(): Promise<void> {
        try {
            const newClient = await this.openvpnService.rotateCertificate(this.options.client);
            newClient.accountStatus = 'Active';
            newClient.revocationDate = undefined;
            this.options.client.accountStatus = 'Revoked';
            this.options.client.revocationDate = new Date();
            this.modal.close(newClient);
        } catch (e) {
            console.warn('service call failed');
        }
    }
}