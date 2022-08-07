import { Component, Injector } from '@angular/core';
import { Sort } from '@angular/material/sort';
import { MatTableDataSource } from '@angular/material/table';
import { ActivatedRoute } from '@angular/router';
import { IClientCertificate } from './models/client-certificate.interface';
import { EditClientComponent, EditClientOptions } from './modals/edit-client.component';
import { NgbModal } from '@ng-bootstrap/ng-bootstrap';
import {
    ConfirmRevokeClientCertificateComponent,
    RevokeClientOptions
} from './modals/confirm-revoke-client-certificate.component';
import { OpenvpnService } from './services/openvpn.service';
import { saveAs } from 'file-saver';
import { CreateClientCertificateComponent } from './modals/create-client-certificate.component';
import {
    ConfirmDeleteClientCertificateComponent,
    DeleteClientOptions
} from './modals/confirm-delete-client-certificate.component';
import {
    ConfirmRotateClientCertificateComponent,
    RotateClientOptions
} from './modals/confirm-rotate-client-certificate.component';

@Component({
    selector: 'ovpn',
    templateUrl: './openvpn.component.html',
    styleUrls: ['./openvpn.component.scss'],
})
export class OpenvpnPageComponent {
    public clients: IClientCertificate[] = [];
    public displayedColumns: string[] = ['username', 'identity', 'accountStatus', 'connections', 'upload-download', 'expirationDate', 'revocationDate', 'actions'];
    public dataSource = new MatTableDataSource<IClientCertificate>();
    public hideRevoked = !!localStorage.getItem('hideRevoked');
    private sort?: Sort;

    constructor(
        private readonly activatedRoute: ActivatedRoute,
        private readonly modalService: NgbModal,
        private readonly injector: Injector,
        private readonly openvpnService: OpenvpnService,
    ) {
        console.warn('clients', this.activatedRoute.snapshot.data.clients);
        this.clients = this.activatedRoute.snapshot.data.clients;
        this.applySorting();
        // this.clients = this.clients.synchronize('peripherals');
        // this.clients.on('update', () => {
        //     this.dataSource.data = [...this.clients.objects];
        // });
    }

    public async revokeClientCertificate(client: IClientCertificate): Promise<void> {
        try {
            console.warn('revoke client certificate', client);
            await this.modalService.open(ConfirmRevokeClientCertificateComponent, {
                centered: true,
                injector: Injector.create([{
                    provide: RevokeClientOptions,
                    useValue: new RevokeClientOptions(client),
                }], this.injector),
            }).result;
            this.applySorting();
        } catch (e) {
            console.warn('Cancel revoke client');
        }
    }

    public async deleteClientCertificate(client: IClientCertificate): Promise<void> {
        try {
            console.warn('delete client certificate', client);
            await this.modalService.open(ConfirmDeleteClientCertificateComponent, {
                centered: true,
                injector: Injector.create([{
                    provide: DeleteClientOptions,
                    useValue: new DeleteClientOptions(client),
                }], this.injector),
            }).result;
            const p = this.clients.indexOf(client);
            if (p === -1) {
                console.warn('Error in UI');
            } else {
                this.clients.splice(p, 1);
            }
            this.applySorting();
        } catch (e) {
            console.warn('Cancel delete client');
        }
    }

    public async unrevokeClientCertificate(client: IClientCertificate): Promise<void> {
        try {
            console.warn('unrevoke client certificate', client);
            await this.openvpnService.unrevokeCertificate(client);
            client.accountStatus = 'Active';
            client.revocationDate = undefined;
            this.applySorting();
        } catch (e) {
            console.warn('Cancel revoke client');
        }
    }

    public async rotateClientCertificate(client: IClientCertificate): Promise<void> {
        try {
            console.warn('rotate client certificate', client);
            const newClient = await this.modalService.open(ConfirmRotateClientCertificateComponent, {
                centered: true,
                injector: Injector.create([{
                    provide: RotateClientOptions,
                    useValue: new RotateClientOptions(client),
                }], this.injector),
            }).result;
            console.warn('new client', newClient);
            this.clients.push(newClient);
            // const p = this.clients.indexOf(client);
            // if (p === -1) {
            //     console.warn('Error in UI');
            // } else {
            //     this.clients.splice(p, 1, newClient);
            // }
            console.warn('all clients', this.clients);
            this.applySorting();
        } catch (e) {
            console.warn('Cancel delete client');
        }
    }

    public async editClient(client: IClientCertificate): Promise<void> {
        console.warn('edit client', client);
        try {
            if (!client.ccd) {
                client.ccd = await this.openvpnService.loadClientConfigDetails(client);
            }
            await this.modalService.open(EditClientComponent, {
                size: 'lg',
                centered: true,
                injector: Injector.create([{
                    provide: EditClientOptions,
                    useValue: new EditClientOptions(client),
                }], this.injector),
            }).result;
            console.warn('client updated');
            this.applySorting();
        } catch (e) {
            console.warn('Cancel edit client');
        }
    }

    public applySorting(): void {
        if (this.sort) {
            this.clients.sort(this.openvpnService.sorter(this.sort));
        }
        if (this.hideRevoked) {
            this.dataSource.data = [...this.clients.filter((client) => !client.revocationDate)];
        } else {
            this.dataSource.data = [...this.clients];
        }
    }

    public async downloadOpenvpnConfig(client: IClientCertificate): Promise<void> {
        const clientConfigFile = await this.openvpnService.loadClientConfig(client);
        saveAs(clientConfigFile, client.username+'.ovpn');
    }

    public async createClientCertificate(): Promise<void> {
        const newClient = await this.modalService.open(CreateClientCertificateComponent, {
            centered: true,
        }).result;
        console.warn('client updated', newClient);
        this.clients.push(newClient);
        this.applySorting();
    }

    public toggleHideRevoked(): void {
        if (this.hideRevoked) {
            localStorage.removeItem('hideRevoked');
            this.hideRevoked = false;
        } else {
            localStorage.setItem('hideRevoked', '1');
            this.hideRevoked = true;
        }
        this.applySorting();
    }

    public sortData(sort: Sort) {
        this.sort = sort;
        this.applySorting();
    }
}
