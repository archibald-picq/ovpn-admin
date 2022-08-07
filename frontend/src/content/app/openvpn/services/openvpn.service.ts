import { Injectable } from '@angular/core';
import { HttpClient, HttpHeaders, HttpParams, HttpResponse } from '@angular/common/http';
import { IClientCertificate } from '../models/client-certificate.interface';
import { ClientCertificate } from '../models/client-certificate.model';
import { filter, map } from 'rxjs/operators';
import { Sort } from '@angular/material/sort';
import { ClientConfig } from '../modals/edit-client.component';
import { Observable, throwError } from 'rxjs';
import { AppConfigService } from '../../shared/services/app-config.service';

@Injectable()
export class OpenvpnService {
    public OPENVPN_ADMIN_API? = '';

    constructor(
        protected readonly http: HttpClient,
        protected readonly appConfigService: AppConfigService,
    ) {
        this.OPENVPN_ADMIN_API = appConfigService.get().openvpn?.url;
        // console.warn('OPENVPN_API_URL', appConfigService.get().openvpn?.url);
    }

    public listClientCertificates(): Observable<IClientCertificate[]> {
        return this.http.get<ClientCertificate[]>(this.OPENVPN_ADMIN_API+'/api/users/list', { observe: 'response'}).pipe(
            filter((response: HttpResponse<any>) => response.ok),
            map((res: any) => res.body as any[]),
            map((items: any[]) => items.map((item: any) => ClientCertificate.parse(item)))
        );
    }

    public loadClientConfigDetails(client: IClientCertificate): Promise<ClientConfig> {
        const params = (new HttpParams()).set('username', client.username);
        return this.http.get<ClientConfig>(this.OPENVPN_ADMIN_API+'/api/user/ccd', {observe: 'response', params}).pipe(
            filter((response: HttpResponse<any>) => response.ok),
            map((res: any) => res.body as Record<string, any>),
            map((item: Record<string, any>) => ClientConfig.parse(item))
        ).toPromise() as Promise<ClientConfig>;
    }

    public createClientCertificat(username: string): Promise<IClientCertificate> {
        // const params = (new HttpParams()).set('username', client.username);
        const body = 'username='+encodeURIComponent(username)+'&password=';
        const headers = new HttpHeaders()
            .set('Content-type', 'application/x-www-form-urlencoded');
        return this.http.post(this.OPENVPN_ADMIN_API+'/api/user/create', body,{
            headers,
            observe: 'response',
            responseType: 'text',
        }).pipe(
            filter((response: HttpResponse<any>) => response.ok),
            map((response) => {
                if (response.body !== `User "${username}" created`) {
                    throwError(() => new Error('Invalid return value'));
                }
            }),
            map(() => ClientCertificate.parse({username})),
        ).toPromise() as Promise<IClientCertificate>;
    }

    public loadClientConfig(client: IClientCertificate): Promise<Blob> {
        const body = 'username='+encodeURIComponent(client.username);
        const headers = new HttpHeaders()
            .set('Content-type', 'application/x-www-form-urlencoded');

        return this.http.post(this.OPENVPN_ADMIN_API+'/api/user/config/show', body, {
            headers,
            observe: 'response',
            responseType: 'blob',
        }).pipe(
            filter((response: HttpResponse<Blob>) => response.ok),
            map((res: HttpResponse<Blob>) => res.body as Blob),
        ).toPromise() as Promise<Blob>;
    }

    public async saveClientConfig(client: IClientCertificate, model: ClientConfig): Promise<void> {
        const body = {
            ClientAddress: model.staticAddress ?? 'dynamic',
            CustomIRoutes: model.iRoutes.map((route) => ({Address: route.address, Mask: route.netmask, Description: route.description})),
            CustomRoutes: model.pushRoutes.map((route) => ({Address: route.address, Mask: route.netmask, Description: route.description})),
            User: client.username,
        };
        return this.http.post(this.OPENVPN_ADMIN_API+'/api/user/ccd/apply', body, {
            observe: 'response',
            responseType: 'text',
        }).pipe(
            filter((response: HttpResponse<any>) => response.ok),
            map((response) => {
                if (response.body !== 'ccd updated successfully') {
                    throwError(() => new Error('Invalid return value'));
                }
            })
        ).toPromise().then();
    }

    public revokeCertificate(client: IClientCertificate): Promise<void> {
        const body = 'username='+encodeURIComponent(client.username);
        const headers = new HttpHeaders()
            .set('Content-type', 'application/x-www-form-urlencoded');
        return this.http.post(this.OPENVPN_ADMIN_API+'/api/user/revoke', body, {
            headers,
            observe: 'response',
            responseType: 'text',
        }).pipe(
            filter((response: HttpResponse<any>) => response.ok),
            map((response) => {
                if (!response.body.match(/An updated CRL has been created/g)) {
                    throwError(() => new Error('Invalid return value'));
                }
            })
        ).toPromise();
    }

    public unrevokeCertificate(client: IClientCertificate): Promise<void> {
        const body = 'username='+encodeURIComponent(client.username);
        const headers = new HttpHeaders()
            .set('Content-type', 'application/x-www-form-urlencoded');
        return this.http.post(this.OPENVPN_ADMIN_API+'/api/user/unrevoke', body, {
            headers,
            observe: 'response',
            // responseType: 'text',
        }).pipe(
            filter((response: HttpResponse<any>) => response.ok),
            map((response) => {
                console.warn('response', response);
                if (response.body.msg === `User ${client.username} successfully unrevoked`) {
                    throwError(() => new Error('Invalid return value'));
                }
            })
        ).toPromise();
    }

    public deleteCertificate(client: IClientCertificate): Promise<void> {
        const body = 'username='+encodeURIComponent(client.username);
        const headers = new HttpHeaders()
            .set('Content-type', 'application/x-www-form-urlencoded');
        return this.http.post(this.OPENVPN_ADMIN_API+'/api/user/delete', body, {
            headers,
            observe: 'response',
            responseType: 'text',
        }).pipe(
            filter((response: HttpResponse<any>) => response.ok),
            map((response) => {
                if (!response.body.match(/An updated CRL has been created/g)) {
                    throwError(() => new Error('Invalid return value'));
                }
            })
        ).toPromise();
    }

    public rotateCertificate(client: IClientCertificate): Promise<IClientCertificate> {
        const body = 'username='+encodeURIComponent(client.username)+'&password=';
        const headers = new HttpHeaders()
            .set('Content-type', 'application/x-www-form-urlencoded');
        return this.http.post(this.OPENVPN_ADMIN_API+'/api/user/rotate', body, {
            headers,
            observe: 'response',
        }).pipe(
            filter((response: HttpResponse<any>) => response.ok),
            map((response) => {
                if (response.body === `User ${client.username} successfully rotated`) {
                    throwError(() => new Error('Invalid return value'));
                }
                return client.clone();
            })
        ).toPromise() as Promise<IClientCertificate>;
        // return new Promise<IClientCertificate>((resolve) => resolve(client.clone()));
    }

    public sorter(sort: Sort) {
        const rev1 = sort.direction === 'asc'? 1: -1;
        const rev2 = sort.direction === 'asc'? -1: 1;
        if (sort.active === 'expirationDate') {
            return (p1: IClientCertificate, p2: IClientCertificate) => {
                const a = p1.expirationDate ?? Infinity;
                const b = p2.expirationDate ?? Infinity;
                return a < b? rev1: (a > b? rev2: 0);
            };
        } else if (sort.active === 'revocationDate') {
            return (p1: IClientCertificate, p2: IClientCertificate) => {
                const a = p1.revocationDate ?? Infinity;
                const b = p2.revocationDate ?? Infinity;
                return a < b? rev1: (a > b? rev2: 0);
            };
        } else if (sort.active === 'username') {
            return (p1: IClientCertificate, p2: IClientCertificate) => {
                const a = p1.username;
                const b = p2.username;
                return a < b? rev1: (a > b? rev2: 0);
            };
        } else if (sort.active === 'identity') {
            return (p1: IClientCertificate, p2: IClientCertificate) => {
                const a = p1.identity;
                const b = p2.identity;
                return a < b? rev1: (a > b? rev2: 0);
            };
        } else if (sort.active === 'accountStatus') {
            return (p1: IClientCertificate, p2: IClientCertificate) => {
                const a = p1.accountStatus;
                const b = p2.accountStatus;
                return a < b? rev1: (a > b? rev2: 0);
            };
        } else if (sort.active === 'connectionStatus') {
            return (p1: IClientCertificate, p2: IClientCertificate) => {
                const a = p1.connectionStatus;
                const b = p2.connectionStatus;
                return a < b? rev1: (a > b? rev2: 0);
            };
        } else if (sort.active === 'connections') {
            return (p1: IClientCertificate, p2: IClientCertificate) => {
                const a = p1.connections;
                const b = p2.connections;
                return a < b? rev1: (a > b? rev2: 0);
            };
        } else {
            return (a: IClientCertificate, b: IClientCertificate) => a < b? rev1: (a > b? rev2: 0);
        }
    }
}