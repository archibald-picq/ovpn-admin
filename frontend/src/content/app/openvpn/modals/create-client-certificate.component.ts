import {Component} from "@angular/core";
import {NgbActiveModal} from "@ng-bootstrap/ng-bootstrap";
import { OpenvpnService } from '../services/openvpn.service';
import { IClientCertificate } from '../models/client-certificate.interface';
import {CertificatInfo} from '../models/certificat-info.model';
//

export class EditCertificatInfo {
    constructor(
      public readonly info: CertificatInfo | undefined,
      public readonly editMode: 'save' | 'return',
      public readonly title: string = 'Create certificate',
  ) {
    }
}

@Component({
    selector: 'bus-openvpn-edit-client-certificate',
    templateUrl: './create-client-certificate.component.html',
    styleUrls: ['./create-client-certificate.component.scss'],
})
export class CreateClientCertificateComponent {
    public certificate: CertificatInfo = {commonName: ''};
    public error = '';
    public loading = false;
    public showHint = true;
    public popupTitle = 'Create certificate';

    constructor(
        private readonly openvpnService: OpenvpnService,
        public readonly modal: NgbActiveModal,
        private readonly options: EditCertificatInfo,
    ) {
        if (options.info) {
            this.certificate.commonName = options.info.commonName;
            this.certificate.email = options.info.email;
            this.certificate.country = options.info.country;
            this.certificate.province = options.info.province;
            this.certificate.city = options.info.city;
            this.certificate.organisation = options.info.organisation;
            this.certificate.organisationUnit = options.info.organisationUnit;
        }
        if (options.editMode === 'return') {
            this.showHint = false;
        }
        if (options.title) {
            this.popupTitle = options.title;
        }
    }

    public async save(): Promise<void> {
        if (this.options.editMode === 'save') {
            try {
                this.loading = true;
                this.error = '';
                const client: IClientCertificate = await this.openvpnService.createClientCertificat(this.certificate);
                console.warn('client created', client);
                this.modal.close(client);
            } catch (e: any) {
                this.error = e.error.message;
                console.warn('service call failed: ', e.error.message);
            }
            this.loading = false;
        } else {
            this.modal.close(this.certificate);
        }
    }

  protected readonly close = close;
}
