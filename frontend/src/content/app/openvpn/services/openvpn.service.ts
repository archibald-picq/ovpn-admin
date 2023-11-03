import { Injectable } from '@angular/core';
import { HttpClient, HttpHeaders, HttpParams, HttpResponse } from '@angular/common/http';
import {IClientCertificate, IConnection} from '../models/client-certificate.interface';
import { ClientCertificate } from '../models/client-certificate.model';
import {filter, map, tap} from 'rxjs/operators';
import { Sort } from '@angular/material/sort';
import {firstValueFrom} from 'rxjs';
import { AppConfigService } from '../../shared/services/app-config.service';
import { ClientConfig } from '../models/client-config.model';
import { OpenvpnConfig } from '../models/openvpn-config.model';
import { NodeConfig } from '../models/node-config.model';

@Injectable()
export class OpenvpnService {
  public OPENVPN_ADMIN_API? = '';
  private config?: Promise<OpenvpnConfig>;

  constructor(
    protected readonly http: HttpClient,
    protected readonly appConfigService: AppConfigService,
  ) {
    this.OPENVPN_ADMIN_API = appConfigService.get().openvpn?.url;
    // console.warn('OPENVPN_API_URL', appConfigService.get().openvpn?.url);
  }

  public loadConfig(): Promise<OpenvpnConfig> {
    if (this.config) {
      return this.config;
    }
    const config = this.appConfigService.get();
    if ((config.openvpn?.settings && config.openvpn?.preferences) || config.openvpn?.unconfigured) {
      this.config = Promise.resolve(config.openvpn);
      return this.config;
    }
    this.config = firstValueFrom(this.http.get<OpenvpnConfig>(this.OPENVPN_ADMIN_API+'/api/config', { observe: 'response'}).pipe(
      filter((response: HttpResponse<any>) => response.ok),
      map((res: any) => res.body as any[]),
      tap(console.warn),
      map(res => OpenvpnConfig.hydrate(res.openvpn)),
      tap(openvpnConfig => {
        config.openvpn = openvpnConfig;
        if (!config.openvpn.url) {
          config.openvpn.url = this.OPENVPN_ADMIN_API;
        }
      })
    ));
    return this.config;
  }

  public listClientCertificates(): Promise<IClientCertificate[]> {
    return firstValueFrom(this.http.get<ClientCertificate[]>(this.OPENVPN_ADMIN_API+'/api/users/list', { observe: 'response'}).pipe(
      filter((response: HttpResponse<any>) => response.ok),
      map((res: any) => res.body as IClientCertificate[]),
      map((items: any[]) => items.map(ClientCertificate.hydrate))
    ));
  }

  public getNodeConfig(clientUsername: string): Promise<NodeConfig> {
    return firstValueFrom(this.http.get<NodeConfig>(this.OPENVPN_ADMIN_API+'/api/node/' + clientUsername, { observe: 'response'}).pipe(
      filter((response: HttpResponse<NodeConfig>) => response.ok),
      map(res => res.body as NodeConfig),
      map(NodeConfig.hydrate)
    ));
  }

  public loadClientConfigDetails(clientUsername: string): Promise<ClientConfig> {
    const params = (new HttpParams()).set('username', clientUsername);
    return firstValueFrom(this.http.get<ClientConfig>(this.OPENVPN_ADMIN_API+'/api/user/ccd', {observe: 'response', params}).pipe(
      filter((response: HttpResponse<any>) => response.ok),
      map((res: any) => res.body as Record<string, any>),
      map(ClientConfig.hydrate)
    ));
  }

  public createClientCertificat(definition: Record<string, string>): Promise<IClientCertificate> {
    return firstValueFrom(this.http.post<IClientCertificate>(this.OPENVPN_ADMIN_API+'/api/user/create', definition,{
      observe: 'response',
    }).pipe(
      filter((response: HttpResponse<IClientCertificate>) => response.ok),
      map((res: any) => res.body as IClientCertificate),
      map(ClientCertificate.hydrate),
    ));
  }

  public loadClientConfig(client: IClientCertificate): Promise<Blob> {
    const body = 'username='+encodeURIComponent(client.username);
    const headers = new HttpHeaders()
      .set('Content-type', 'application/x-www-form-urlencoded');

    return firstValueFrom(this.http.post(this.OPENVPN_ADMIN_API+'/api/user/config/show', body, {
      headers,
      observe: 'response',
      responseType: 'blob',
    }).pipe(
      filter((response: HttpResponse<Blob>) => response.ok),
      map((res: HttpResponse<Blob>) => res.body as Blob),
    ));
  }

  public async saveServerConfig(toSave: Record<string, any>): Promise<any> {
    return firstValueFrom(this.http.post(this.OPENVPN_ADMIN_API+'/api/config/settings/save', toSave, {
      observe: 'response',
    }).pipe(
      filter((response: HttpResponse<any>) => response.ok),
    ));
  }

  public async savePreferences(toSave: Record<string, any>): Promise<any> {
    return firstValueFrom(this.http.post(this.OPENVPN_ADMIN_API+'/api/config/preferences/save', toSave, {
      observe: 'response',
    }).pipe(
      filter((response: HttpResponse<any>) => response.ok),
    ));
  }

  public async saveClientConfig(client: IClientCertificate, model: ClientConfig): Promise<void> {
    const body = {
      clientAddress: model.staticAddress ?? 'dynamic',
      customIRoutes: model.iRoutes.map((route) => ({address: route.address, netmask: route.netmask, description: route.description})),
      customRoutes: model.pushRoutes.map((route) => ({address: route.address, netmask: route.netmask, description: route.description})),
      user: client.username,
    };
    return firstValueFrom(this.http.post(this.OPENVPN_ADMIN_API+'/api/user/ccd/apply', body, {
      observe: 'response',
    }).pipe(
      filter((response: HttpResponse<any>) => response.ok),
    )).then();
  }

  public revokeCertificate(client: IClientCertificate): Promise<any> {
    const body = 'username='+encodeURIComponent(client.username);
    const headers = new HttpHeaders()
      .set('Content-type', 'application/x-www-form-urlencoded');
    return firstValueFrom(this.http.post(this.OPENVPN_ADMIN_API+'/api/user/revoke', body, {
      headers,
      observe: 'response',
      responseType: 'text',
    }).pipe(
      filter((response: HttpResponse<any>) => response.ok),
    ));
  }

  public killConnection(client: IClientCertificate, conn: IConnection): Promise<void> {
    const body = {
      clientId: conn.clientId,
    }
    return firstValueFrom(this.http.post(this.OPENVPN_ADMIN_API+'/api/user/kill', body, {
      // headers,
      observe: 'response',
      // responseType: 'text',
    }).pipe(
      filter((response: HttpResponse<any>) => response.ok),
      map((response) => {
        console.warn('response', response);
        const p = client.connections.indexOf(conn);
        if (p !== -1) {
          client.connections.splice(p, 1);
        } else {
          console.warn('Cant find connection by reference', conn, client.connections);
        }
        // if (response.body.msg === `User ${client.username} successfully unrevoked`) {
        //     throwError(() => new Error('Invalid return value'));
        // }
      })
    ));
  }

  public unrevokeCertificate(client: IClientCertificate): Promise<any> {
    const body = 'username='+encodeURIComponent(client.username);
    const headers = new HttpHeaders()
      .set('Content-type', 'application/x-www-form-urlencoded');
    return firstValueFrom(this.http.post(this.OPENVPN_ADMIN_API+'/api/user/unrevoke', body, {
      headers,
      observe: 'response',
      // responseType: 'text',
    }).pipe(
      filter((response: HttpResponse<any>) => response.ok),
    ));
  }

  public deleteCertificate(client: IClientCertificate): Promise<any> {
    const body = 'username='+encodeURIComponent(client.username);
    const headers = new HttpHeaders()
      .set('Content-type', 'application/x-www-form-urlencoded');
    return firstValueFrom(this.http.post(this.OPENVPN_ADMIN_API+'/api/user/delete', body, {
      headers,
      observe: 'response',
      responseType: 'text',
    }).pipe(
      filter((response: HttpResponse<any>) => response.ok),
    ));
  }

  public rotateCertificate(client: IClientCertificate): Promise<IClientCertificate> {
    const body = 'username='+encodeURIComponent(client.username)+'&password=';
    const headers = new HttpHeaders()
      .set('Content-type', 'application/x-www-form-urlencoded');
    return firstValueFrom(this.http.post(this.OPENVPN_ADMIN_API+'/api/user/rotate', body, {
      headers,
      observe: 'response',
    }).pipe(
      filter((response: HttpResponse<any>) => response.ok),
      map(() => client.clone())
    ));
    // return new Promise<IClientCertificate>((resolve) => resolve(client.clone()));
  }

  public sorter(sort: Sort) {
    const rev1 = sort.direction === 'asc'? 1: -1;
    const rev2 = sort.direction === 'asc'? -1: 1;
    if (sort.active === 'expirationDate') {
      return (p1: IClientCertificate, p2: IClientCertificate) => {
        const a = p1.certificate!.expirationDate ?? Infinity;
        const b = p2.certificate!.expirationDate ?? Infinity;
        return a < b? rev1: (a > b? rev2: 0);
      };
    } else if (sort.active === 'revocationDate') {
      return (p1: IClientCertificate, p2: IClientCertificate) => {
        const a = p1.certificate!.revocationDate ?? Infinity;
        const b = p2.certificate!.revocationDate ?? Infinity;
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
        const a = p1.certificate!.identity;
        const b = p2.certificate!.identity;
        return a < b? rev1: (a > b? rev2: 0);
      };
    } else if (sort.active === 'accountStatus') {
      return (p1: IClientCertificate, p2: IClientCertificate) => {
        const a = p1.certificate!.accountStatus;
        const b = p2.certificate!.accountStatus;
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
