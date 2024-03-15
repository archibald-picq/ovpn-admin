import {Injectable} from '@angular/core';
import {ClientCertificate} from '../models/client-certificate.model';
import {ClientConfig} from '../models/client-config.model';
import {IConnection} from '../models/client-certificate.interface';

@Injectable()
export class CsvService {
  public build(clients: ClientCertificate[], separator = ';'): string[] {
    console.warn('clients', clients);

    const lines = [
      this.buildCsvLine(separator, [
        'common_name',
        'country',
        'province',
        'city',
        'organisation',
        'organisationUnit',
        'email',
        'expirationDate',
        'revocationDate',
        'currentConnection',
        'staticAddress',
        'customRoutes',
        'customIRoutes',
        'connection',
      ]),
      ... clients.map(client => this.buildCsvLine(separator, [
        client.username,
        client.certificate?.country ?? '',
        client.certificate?.province ?? '',
        client.certificate?.city ?? '',
        client.certificate?.organisation ?? '',
        client.certificate?.organisationUnit ?? '',
        client.certificate?.email ?? '',
        client.certificate?.expirationDate?.toISOString() ?? '',
        client.certificate?.revocationDate?.toISOString() ?? '',
        this.getCurrentConnection(client.connections),
        this.getStaticAddress(client.ccd),
        this.getCustomRoutes(client.ccd),
        this.getCustomIRoutes(client.ccd),
      ])),
    ];



    return lines;
  }

  private getStaticAddress(ccd: ClientConfig | undefined) {
    return ccd?.clientAddress === 'dynamic' ? '' : (ccd?.clientAddress ?? '');
  }

  private buildCsvLine(separator: string, cells: string[]): string {
    const cellsProtected = cells.map(f => {
      let needQuotes = false;
      if (f !== undefined && f.indexOf(separator) !== -1) {
        f = f.replace(/"/g, '\\"');
        needQuotes = true;
      }
      if (f !== undefined && f.indexOf("\n") !== -1) {
        needQuotes = true;
      }
      if (needQuotes) {
        f = '"'+f+'"';
      }
      return f;
    })
    return cellsProtected.join(separator);
  }

  private getCustomRoutes(ccd: ClientConfig | undefined) {
    return ccd?.customRoutes.map(r => r.address + '/' + r.netmask + (r.description ? ' # ' + r.description : '')).join("\n") ?? '';
  }
  private getCustomIRoutes(ccd: ClientConfig | undefined) {
    return ccd?.customIRoutes.map(r => r.address + '/' + r.netmask + (r.description ? ' # ' + r.description : '')).join("\n") ?? '';
  }

  private getCurrentConnection(client: IConnection[]) {
    return client.length > 0 ? client[0].realAddress : '';
  }
}
