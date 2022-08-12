import {Component} from "@angular/core";
import {NgbActiveModal} from "@ng-bootstrap/ng-bootstrap";
import { OpenvpnService } from '../services/openvpn.service';
import { IClientCertificate } from '../models/client-certificate.interface';


@Component({
    selector: 'bus-openvpn-confirm-revoke-client-certificate',
    templateUrl: './create-client-certificate.component.html',
    styleUrls: ['./create-client-certificate.component.scss'],
})
export class CreateClientCertificateComponent {
    public username = '';
    public email = '';
    public country = '';
    public province = '';
    public city = '';
    public organisation = '';
    public organisationUnit = '';
    public error = '';
    public loading = false;

    constructor(
        private readonly openvpnService: OpenvpnService,
        public readonly modal: NgbActiveModal,
    ) {
    }

    public async save(): Promise<void> {
        try {
            this.loading = true;
            this.error = '';
            const client: IClientCertificate = await this.openvpnService.createClientCertificat({
                username: this.username,
                email: this.email,
                country: this.country,
                province: this.province,
                city: this.city,
                organisation: this.organisation,
                organisationUnit: this.organisationUnit,
            });
            console.warn('client created', client);
            this.modal.close(client);
        } catch (e: any) {
            this.error = e.error.message;
            console.warn('service call failed: ', e.error.message);
        }
        this.loading = false;
    }
}