import { Injectable } from '@angular/core';
import { HttpClient, HttpResponse } from '@angular/common/http';
import {IClientCertificate, IConnection} from '../models/client-certificate.interface';
import { ClientCertificate } from '../models/client-certificate.model';
import {filter, map, tap} from 'rxjs/operators';
import { Sort } from '@angular/material/sort';
import {firstValueFrom} from 'rxjs';
import { AppConfigService } from '../../shared/services/app-config.service';
import { ClientConfig } from '../models/client-config.model';
import { OpenvpnConfig } from '../models/openvpn-config.model';
import { NodeConfig } from '../models/node-config.model';
import {IRevokedCertificate} from '../models/revoked-certificate.interface';
import {CreateCertificateDefinition} from '../models/create-certificate.interface';

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

  public async loadConfig(): Promise<OpenvpnConfig> {
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

  public async listClientCertificates(): Promise<IClientCertificate[]> {
    return firstValueFrom(this.http.get<ClientCertificate[]>(this.OPENVPN_ADMIN_API+'/api/user/')).then(
      (items) => items.map(ClientCertificate.hydrate)
    );
  }

  public async getNodeConfig(clientUsername: string): Promise<NodeConfig> {
    return firstValueFrom(this.http.get<NodeConfig>(this.OPENVPN_ADMIN_API+'/api/node/' + clientUsername)).then(
      NodeConfig.hydrate
    );
  }

  // public async loadClientConfigDetails(clientUsername: string): Promise<ClientConfig> {
  //   return firstValueFrom(this.http.get<ClientConfig>(this.OPENVPN_ADMIN_API+'/api/user/'+clientUsername+'/ccd'))
  //     .then(ClientConfig.hydrate);
  // }

  public async createClientCertificat(definition: CreateCertificateDefinition): Promise<ClientCertificate> {
    return firstValueFrom(this.http.post<IClientCertificate>(this.OPENVPN_ADMIN_API+'/api/user/', definition)).then(
      ClientCertificate.hydrate,
    );
  }

  public async loadClientConfig(client: { username:string }): Promise<Blob> {
    return firstValueFrom(this.http.get(this.OPENVPN_ADMIN_API+'/api/user/' + client.username + '/conf', {
      responseType: 'blob',
    }));
  }

  public async listCrl(): Promise<IRevokedCertificate> {
    return firstValueFrom(this.http.get<IRevokedCertificate[]>(this.OPENVPN_ADMIN_API+'/api/openvpn/crl'));
  }

  public async saveServerConfig(toSave: Record<string, any>): Promise<any> {
    return firstValueFrom(this.http.post(this.OPENVPN_ADMIN_API+'/api/config/settings/save', toSave, {
      observe: 'response',
    }).pipe(
      filter((response: HttpResponse<any>) => response.ok),
    ));
  }

  public async savePreferences(toSave: Record<string, any>): Promise<void> {
    return firstValueFrom(this.http.post<void>(this.OPENVPN_ADMIN_API+'/api/config/preferences/save', toSave));
  }

  public async saveClientConfig(client: IClientCertificate, model: ClientConfig): Promise<void> {
    const body = {
      clientAddress: model.clientAddress ?? 'dynamic',
      customIRoutes: model.customIRoutes.map((route) => ({address: route.address, netmask: route.netmask, description: route.description})),
      customRoutes: model.customRoutes.map((route) => ({address: route.address, netmask: route.netmask, description: route.description})),
    };
    return firstValueFrom(this.http.put<void>(this.OPENVPN_ADMIN_API+'/api/user/'+client.username+'/ccd', body));
  }

  public async revokeCertificate(client: IClientCertificate): Promise<void> {
    return firstValueFrom(this.http.post<void>(this.OPENVPN_ADMIN_API+'/api/user/'+client.username+'/revoke', {}));
  }

  public async killConnection(client: IClientCertificate, conn: IConnection): Promise<void> {
    const body = {
      clientId: conn.clientId,
    }
    return firstValueFrom(this.http.post<void>(this.OPENVPN_ADMIN_API+'/api/user/'+client.username+'/kill', body))
      .then((response) => {
        console.warn('response', response);
        const p = client.connections.indexOf(conn);
        if (p !== -1) {
          client.connections.splice(p, 1);
        } else {
          console.warn('Cant find connection by reference', conn, client.connections);
        }
      });
  }

  public async unrevokeCertificate(client: IClientCertificate): Promise<any> {
    return firstValueFrom(this.http.post(this.OPENVPN_ADMIN_API+'/api/user/'+client.username+'/unrevoke', {}));
  }

  public async deleteCertificate(client: IClientCertificate): Promise<void> {
    return firstValueFrom(this.http.delete<void>(this.OPENVPN_ADMIN_API+'/api/user/'+client.username+'/'));
  }

  public async rotateCertificate(client: IClientCertificate): Promise<IClientCertificate> {
    const body = {password: ''};
    return firstValueFrom(this.http.post<IClientCertificate>(this.OPENVPN_ADMIN_API+'/api/user/' + client.username + '/rotate', body)).then(
      () => client.clone()
    );
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


  public isInNetwork(ip: string, net: string) {
    const [network, mask] = net.split('/');
    // eslint-disable-next-line no-bitwise
    return (this.ipToNumber(ip) & this.ipMask(+mask)) === this.ipToNumber(network);
  }

  private ipToNumber(ip: string): number {
    const p = ip.match(/^(\d+)\.(\d+)\.(\d+)\.(\d+)$/);
    if (p) {
      // eslint-disable-next-line no-bitwise
      return (+p[1]<<24) + (+p[2]<<16) + (+p[3]<<8) + (+p[4]);
    }
    return NaN;
  }

  private ipMask(size: number): number {
    // eslint-disable-next-line no-bitwise
    return -1 << (32 - size);
  }
}
