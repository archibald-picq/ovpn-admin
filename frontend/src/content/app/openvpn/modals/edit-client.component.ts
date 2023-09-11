import {Component} from "@angular/core";
import {NgbActiveModal} from "@ng-bootstrap/ng-bootstrap";
import { IClientCertificate } from "../models/client-certificate.interface";
import { OpenvpnService } from '../services/openvpn.service';
import { ClientConfig } from '../models/client-config.model';
import { Route } from '../models/route.model';

export class EditClientOptions {
    constructor(public readonly client: IClientCertificate) {
    }
}

@Component({
    selector: 'bus-openvpn-edit-client',
    templateUrl: './edit-client.component.html',
    styleUrls: ['./edit-client.component.scss'],
})
export class EditClientComponent {
    public model: ClientConfig;
    public certificate: IClientCertificate;
    public newPushRoute = new Route('', '');
    public newIRoute = new Route('', '');
    public error = '';
    public loading = false;

    constructor(
        private readonly openvpnService: OpenvpnService,
        public readonly modal: NgbActiveModal,
        public readonly options: EditClientOptions,
    ) {
        this.certificate = this.options.client;
        if (this.options.client.ccd) {
            this.model = this.options.client.ccd.clone();
        } else {
            this.model = new ClientConfig('', [], []);
        }

        if (this.model.staticAddress === 'dynamic') {
            this.model.staticAddress = '';
        }
        // console.warn('this.model.staticAddress', this.model.staticAddress);
    }

    public removePushRoute(route: Route): void {
        const p = this.model.pushRoutes.indexOf(route);
        if (p === -1) {
            console.warn('Error in page');
            return;
        }
        this.model.pushRoutes.splice(p, 1);
    }

    public removeIRoute(route: Route): void {
        const p = this.model.iRoutes.indexOf(route);
        if (p === -1) {
            console.warn('Error in page');
            return;
        }
        this.model.iRoutes.splice(p, 1);
    }

    public addPushRoute(): void {
        this.model.pushRoutes.push(this.newPushRoute.clone());
        this.newPushRoute.reset();
    }

    public addIRoute(): void {
        this.model.iRoutes.push(this.newIRoute.clone());
        this.newIRoute.reset();
    }

    public clearFixedIp(): void {
        console.warn('clearFixedIp');
    }

    public async save(): Promise<void> {
        this.loading = true;
        try {
            this.error = '';
            await this.openvpnService.saveClientConfig(this.options.client, this.model);
            this.options.client.ccd = this.model;
            this.modal.close('Save click');
        } catch (e: any) {
            this.error = e.error.message;
        }
        this.loading = false;
    }
}
