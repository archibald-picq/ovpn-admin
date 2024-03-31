import {Component} from "@angular/core";
import {NgbActiveModal} from "@ng-bootstrap/ng-bootstrap";
import { OpenvpnService } from '../services/openvpn.service';
import { IClientCertificate } from '../models/client-certificate.interface';
//
export interface CertificatInfo {
    commonName: string;
    email: string;
    country: string;
    province: string;
    city: string;
    organisation: string;
    organisationUnit: string;
}

export class EditCertificatInfo {
    constructor(public readonly info: CertificatInfo | undefined, public readonly editMode: 'save' | 'return') {
    }
}

@Component({
    selector: 'bus-openvpn-edit-client-certificate',
    templateUrl: './create-client-certificate.component.html',
    styleUrls: ['./create-client-certificate.component.scss'],
})
export class CreateClientCertificateComponent {
    public commonName = '';
    public email = '';
    public country = '';
    public province = '';
    public city = '';
    public organisation = '';
    public organisationUnit = '';
    public error = '';
    public loading = false;
    public showHint = true;

    constructor(
        private readonly openvpnService: OpenvpnService,
        public readonly modal: NgbActiveModal,
        private readonly options: EditCertificatInfo,
    ) {
        if (options.info) {
            this.commonName = options.info.commonName;
            this.email = options.info.email;
            this.country = options.info.country;
            this.province = options.info.province;
            this.city = options.info.city;
            this.organisation = options.info.organisation;
            this.organisationUnit = options.info.organisationUnit;
        }
        if (this.options.editMode === 'return') {
            this.showHint = false;
        }
    }

    public async save(): Promise<void> {
        if (this.options.editMode === 'save') {
            try {
                this.loading = true;
                this.error = '';
                const client: IClientCertificate = await this.openvpnService.createClientCertificat({
                    commonName: this.commonName,
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
        } else {
            this.modal.close({
                commonName: this.commonName,
                email: this.email,
                city: this.city,
                country: this.country,
                province: this.province,
                organisation: this.organisation,
                organisationUnit: this.organisationUnit,
            } as CertificatInfo);
        }
    }

  protected readonly close = close;
}
