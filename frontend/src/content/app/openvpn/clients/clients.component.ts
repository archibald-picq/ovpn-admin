import {Component, Injector, OnDestroy, OnInit} from '@angular/core';
import { Sort } from '@angular/material/sort';
import { MatTableDataSource } from '@angular/material/table';
import { ActivatedRoute } from '@angular/router';
import { IClientCertificate, IConnection } from '../models/client-certificate.interface';
import { EditClientComponent, EditClientOptions } from '../modals/edit-client.component';
import { NgbModal } from '@ng-bootstrap/ng-bootstrap';
import {
    ConfirmRevokeClientCertificateComponent,
    RevokeClientOptions
} from '../modals/confirm-revoke-client-certificate.component';
import { OpenvpnService } from '../services/openvpn.service';
import { saveAs } from 'file-saver';
import { CreateClientCertificateComponent } from '../modals/create-client-certificate.component';
import {
    ConfirmDeleteClientCertificateComponent,
    DeleteClientOptions
} from '../modals/confirm-delete-client-certificate.component';
import {
    ConfirmRotateClientCertificateComponent,
    RotateClientOptions
} from '../modals/confirm-rotate-client-certificate.component';
import {WebsocketService} from "../services/websocket.service";
import {ClientCertificate} from "../models/client-certificate.model";
import {ConfirmKillConnectionComponent, KillConnectionOptions} from "../modals/confirm-kill-connection.component";

@Component({
    selector: 'bus-openvpn-clients',
    templateUrl: './clients.component.html',
    styleUrls: ['./clients.component.scss'],
})
export class OpenvpnClientsComponent implements OnInit, OnDestroy {
    public clients: IClientCertificate[] = [];
    public displayedColumns: string[] = ['username', /* 'accountStatus', */ 'connections', 'speed-upload-download', 'upload-download', 'expirationDate', 'actions'];
    public dataSource = new MatTableDataSource<IClientCertificate>();
    public hideRevoked = !!localStorage.getItem('hideRevoked');
    private sort?: Sort;
    public minSpeedThreshold = 1024; // don't show speed lower thant 1kb/s

    private usersCallback = (data: any) => {
        this.mergeLists(this.clients, data);
    };

    private userUpdateCallback = (data: any) => {
        this.updateLists(this.clients, data);
    };

    constructor(
        private readonly activatedRoute: ActivatedRoute,
        private readonly modalService: NgbModal,
        private readonly injector: Injector,
        private readonly openvpnService: OpenvpnService,
        private readonly websocketService: WebsocketService,
    ) {
        this.clients = this.activatedRoute.snapshot.data.clients;
        this.applySorting();
        if (!this.hideRevoked) {
            this.addRevocationDateColumnBeforeActions();
        }
        // this.clients = this.clients.synchronize('peripherals');
        // this.clients.on('update', () => {
        //     this.dataSource.data = [...this.clients.objects];
        // });
    }

    ngOnInit(): void {
        this.websocketService.bind('users', this.usersCallback);
        this.websocketService.bind('user.update', this.userUpdateCallback);
    }

    ngOnDestroy(): void {
        this.websocketService.unbind('user.update', this.userUpdateCallback);
        this.websocketService.unbind('users', this.usersCallback);
    }

    public async revokeClientCertificate(client: IClientCertificate): Promise<void> {
        try {
            console.warn('revoke client certificate', client);
            await this.modalService.open(ConfirmRevokeClientCertificateComponent, {
                centered: true,
                injector: Injector.create({
                    providers: [{
                        provide: RevokeClientOptions,
                        useValue: new RevokeClientOptions(client),
                    }],
                    parent: this.injector,
                }),
            }).result;
            client.connections.splice(0, client.connections.length);
            client.connectionStatus = '';
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

    public async killConnection(client: IClientCertificate, connection: IConnection): Promise<void> {
        // console.warn('Kill connection to '+client.username+' #'+connection.clientId);
        try {
            await this.modalService.open(ConfirmKillConnectionComponent, {
                centered: true,
                injector: Injector.create([{
                    provide: KillConnectionOptions,
                    useValue: new KillConnectionOptions(client, connection),
                }], this.injector),
            }).result;
        } catch (e) {
            console.warn('Cancel confirmation kill connection', e)
        }
    }

    public async unrevokeClientCertificate(client: IClientCertificate): Promise<void> {
        try {
            console.warn('unrevoke client certificate', client);
            await this.openvpnService.unrevokeCertificate(client);
            client.certificate!.accountStatus = 'Active';
            client.certificate!.revocationDate = undefined;
            this.applySorting();
        } catch (e) {
            console.warn('Cancel revoke client', e);
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
                client.ccd = await this.openvpnService.loadClientConfigDetails(client.username);
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

    private addRevocationDateColumnBeforeActions(): void {
        const p = this.displayedColumns.indexOf('revocationDate');
        if (p === -1) {
            const q = this.displayedColumns.indexOf('actions');
            if (q === -1) {
                this.displayedColumns.push('revocationDate');
            } else {
                this.displayedColumns.splice(q, 0, 'revocationDate');
            }
        }
    }

    public applySorting(): void {
        if (this.sort) {
            this.clients.sort(this.openvpnService.sorter(this.sort));
        }
        if (this.hideRevoked) {
            this.dataSource.data = [...this.clients.filter((client) => !client.certificate!.revocationDate)];
            const p = this.displayedColumns.indexOf('revocationDate');
            if (p !== -1) {
                this.displayedColumns.splice(p, 1);
            }
        } else {
            this.dataSource.data = [...this.clients];
            this.addRevocationDateColumnBeforeActions();
        }
    }

    public async downloadOpenvpnConfig(client: IClientCertificate): Promise<void> {
        const clientConfigFile = await this.openvpnService.loadClientConfig(client);
        saveAs(clientConfigFile, client.username+'.ovpn');
    }

    public async createClientCertificate(): Promise<void> {
        try {
            const newClient = await this.modalService.open(CreateClientCertificateComponent, {
                centered: true,
            }).result;
            console.warn('client updated', newClient);
            this.clients.push(newClient);
            this.applySorting();
        } catch (e) {
            console.warn('Cancel create client');
        }
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

    public sumSpeedBytesReceived(connections: IConnection[]): number {
        return connections.reduce((acc, conn) => acc + conn.speedBytesReceived, 0) / connections.length;
    }
    public sumBytesReceived(connections: IConnection[]): number {
        return connections.reduce((acc, conn) => acc + conn.bytesReceived, 0);
    }
    public sumSpeedBytesSent(connections: IConnection[]): number {
        return connections.reduce((acc, conn) => acc + conn.speedBytesSent, 0) / connections.length;
    }
    public sumBytesSent(connections: IConnection[]): number {
        return connections.reduce((acc, conn) => acc + conn.bytesSent, 0);
    }
    public cleanEntity(entity: string): string {
        return entity.replace(/^\//, '').replace(/\//g, "\n");
    }

    private mergeLists(clients: IClientCertificate[], data: any) {
        if (!data.map) {
            console.warn('newClients', data);
        }
        const newClients = data.map(ClientCertificate.hydrate);
        const obsoletes = [...clients];
        newClients.forEach((newClient: IClientCertificate) => {
            const old = clients.find((c) => c.username === newClient.username);
            if (old) {
                old.merge(newClient);
                // newClients.splice(i, 1);
                const oldObs = obsoletes.indexOf(old);
                if (oldObs !== -1) {
                    obsoletes.splice(oldObs, 1);
                // } else {
                //     console.warn('Cant find old client', old, 'in obsolete list');
                }
            } else {
                clients.push(newClient);
            }
        });
        // console.warn('remaining obsolete clients', obsoletes);
        obsoletes.forEach((obs) => {
            const idx = clients.indexOf(obs);
            if (idx !== -1) {
                clients.splice(idx, 1);
            // } else {
            //     console.warn('Cant find absolete client', obs, 'in obsolete list');
            }
        });

    }

    private updateLists(clients: IClientCertificate[], data: any) {
        if (!data.map) {
            console.warn('newClients', data);
        }
        const newClients = data.map(ClientCertificate.hydrate);
        newClients.forEach((newClient: IClientCertificate) => {
            const old = clients.find((c) => c.username === newClient.username);
            if (old) {
                old.merge(newClient);
            } else {
                console.warn('Cant find old client', old, 'in obsolete list');
            }
        });
    }
}
