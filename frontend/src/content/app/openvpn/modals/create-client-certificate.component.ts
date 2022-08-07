import {Component} from "@angular/core";
import {NgbActiveModal} from "@ng-bootstrap/ng-bootstrap";
import { OpenvpnService } from '../services/openvpn.service';
import { IClientCertificate } from '../models/client-certificate.interface';


@Component({
    selector: 'bus-openvpn-confirm-revoke-client-certificate',
    templateUrl: './create-client-certificate.component.html',
    styleUrls: ['../openvpn.component.scss'],
})
export class CreateClientCertificateComponent {
    public username = '';
    constructor(
        private readonly openvpnService: OpenvpnService,
        public readonly modal: NgbActiveModal,
    ) {

    }

    public async save(): Promise<void> {
        try {
            const client: IClientCertificate = await this.openvpnService.createClientCertificat(this.username);
            console.warn('client created', client);
            this.modal.close(client);
        } catch (e) {
            console.warn('service call failed: ', e);
        }
    }
}