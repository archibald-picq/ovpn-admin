import {Component} from "@angular/core";
import {NgbActiveModal} from "@ng-bootstrap/ng-bootstrap";
import { OpenvpnService } from '../services/openvpn.service';
import {IClientCertificate, IConnection} from "../models/client-certificate.interface";

export class KillConnectionOptions {
    constructor(
      public readonly user: IClientCertificate,
      public readonly connection: IConnection,
  ) {}
}

@Component({
    selector: 'bus-openvpn-confirm-kill-connection',
    templateUrl: './confirm-kill-connection.component.html',
    styleUrls: ['./confirm-kill-connection.component.scss'],
})
export class ConfirmKillConnectionComponent {
    public error = '';
    public loading = false;

    constructor(
        public readonly openvpnService: OpenvpnService,
        public readonly modal: NgbActiveModal,
        public readonly options: KillConnectionOptions,
    ) {

    }

    public async save(): Promise<void> {
        try {
            this.loading = true;
            await this.openvpnService.killConnection(this.options.user, this.options.connection);
            this.modal.close(true);
        } catch (e) {
            console.warn('service call failed', e);
            this.error = (e as any).error.message;
        }
        this.loading = false;
    }
}
