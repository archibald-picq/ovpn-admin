import { Component, Injector } from '@angular/core';
import { ActivatedRoute } from '@angular/router';
import { NgbModal } from '@ng-bootstrap/ng-bootstrap';
import { OpenvpnService } from '../services/openvpn.service';
import { OpenvpnConfig } from '../models/openvpn-config.model';
import { Route } from '../models/route.model';


@Component({
    selector: 'bus-openvpn-settings',
    templateUrl: './settings.component.html',
    styleUrls: ['./settings.component.scss'],
})
export class OpenvpnSettingsPageComponent {
    public loading = false;
    public model: OpenvpnConfig;
    public originalConfig: OpenvpnConfig;
    public newPush = new Route('', '');
    public newRoute = new Route('', '');
    public enableIpv4 = false;
    public enableIpv6 = false;
    public error = '';
    private serialized = '';

    constructor(
        private readonly activatedRoute: ActivatedRoute,
        private readonly modalService: NgbModal,
        private readonly injector: Injector,
        private readonly openvpnService: OpenvpnService,
    ) {
        console.warn('config', this.activatedRoute.snapshot.data.config);
        this.originalConfig = this.activatedRoute.snapshot.data.config;
        this.model = this.originalConfig.clone();
        // console.warn('this.model', this.model.routes);
        if (this.model.server) {
            this.enableIpv4 = true;
        }
        if (this.model.serverIpv6) {
            this.enableIpv6 = true;
        }
        this.serialized = JSON.stringify(this.toSave());
    }

    public removePush(route: Route): void {
        const p = this.model.pushs.indexOf(route);
        if (p === -1) {
            console.warn('Error in page');
            return;
        }
        this.model.pushs.splice(p, 1);
    }

    public removeRoute(route: Route): void {
        const p = this.model.routes.indexOf(route);
        if (p === -1) {
            console.warn('Error in page');
            return;
        }
        this.model.routes.splice(p, 1);
    }

    public addPush(): void {
        this.model.pushs.push(this.newPush.clone());
        this.newPush.reset();
    }

    public addRoute(): void {
        this.model.routes.push(this.newRoute.clone());
        this.newRoute.reset();
    }

    public async save(): Promise<void> {
        try {
            this.loading = true;
            this.error = '';
            const toSave = this.toSave();
            await this.openvpnService.saveServerConfig(toSave);
            Object.assign(this.originalConfig, toSave);
            this.serialized = JSON.stringify(toSave);
            this.loading = false;
        } catch (e: any) {
            this.loading = false;
            this.error = e.error.message;
            console.warn('Error saving', e);
        }
    }

    private toSave(): Record<string, any> {
        return {
            server: this.model.server,
            serverIpv6: this.model.serverIpv6,
            compLzo: this.model.compLzo,
            duplicateCn: this.model.duplicateCn,
        };
    }

    public hasPendingChanges(): boolean {
        return this.serialized !== JSON.stringify(this.toSave());
    }
}
