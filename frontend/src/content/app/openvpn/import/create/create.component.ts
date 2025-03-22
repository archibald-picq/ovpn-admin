import {Component, Inject, Injector} from '@angular/core';
import {ActivatedRoute, Router} from '@angular/router';
import {CreateCertificateBatchInfo} from '../model/create-certificate-batch-info.model';
import {MatTableDataSource} from '@angular/material/table';
import {ClientCertificate} from '../../models/client-certificate.model';
import {Sort} from '@angular/material/sort';
import {OpenvpnService} from '../../services/openvpn.service';
import {saveAs} from 'file-saver';
import {OpenvpnComponent} from '../../openvpn.component';
import {Settings} from '../../models/openvpn-config.model';
import {NgbModal} from '@ng-bootstrap/ng-bootstrap';
import {
  CreateClientCertificateComponent,
  EditCertificatInfo
} from '../../modals/create-client-certificate.component';
import {ICcd} from '../../models/client-certificate.interface';
import {BaseCertificate} from '../../models/certificate-base.interface';
import {ClientConfig} from '../../models/client-config.model';
import {CertificatInfo} from '../../models/certificat-info.model';

@Component({
  selector: 'bus-import-create',
  templateUrl: './create.component.html',
  styleUrls: ['./create.component.scss'],
})
export class ImportCreateComponent {
  public clients: ClientCertificate[] = [];
  public list: CreateCertificateBatchInfo[];
  public dataSource = new MatTableDataSource<CreateCertificateBatchInfo>();
  public error?: string;
  public loading = false;

  public displayedColumns: string[] = [
    'creationStatus',
    'commonName',
    'email',
    'identity',
    'staticAddress',
    // 'expirationDate',
    'actions',
  ];
  private sort?: Sort;
  private settings: Settings;

  constructor(
    // private readonly route: ActivatedRoute,
    private readonly router: Router,
    private readonly activatedRoute: ActivatedRoute,
    private readonly openvpnService: OpenvpnService,
    @Inject(OpenvpnComponent) public readonly parent: OpenvpnComponent,
    private readonly injector: Injector,
    private readonly modalService: NgbModal,
  ) {
    this.clients = this.activatedRoute.snapshot.data.clients || [];
    this.settings = this.activatedRoute.parent?.parent?.snapshot.data.config.settings;
    // console.warn('parent.config', this.parent?.config);
    // this.globalSettings = this.activatedRoute.parent && this.activatedRoute.parent.parent ? this.activatedRoute.parent.parent.data['config']?.settings : undefined;
    // const globalSettings = this.activatedRoute.parent?.snapshot.data.config.settings;
    // console.warn('this.clients', this.clients);
    // const state = route.snapshot.data;
    const importedCertificates = router.getCurrentNavigation()?.extras.state?.importedCertificates;
    const prevState = localStorage.getItem('tmp-import');
    if (importedCertificates) {
      this.list = importedCertificates;
      localStorage.setItem('tmp-import', JSON.stringify(this.list));
      // console.warn('Using certificates', importedCertificates);
      this.updateAllStatus();
      this.applySorting();
      return;
    }
    try {
      if (prevState) {
        const prevCertificates = JSON.parse(prevState).map(CreateCertificateBatchInfo.hydrate);
        this.list = prevCertificates;
        // console.warn('Using recovered certificates', prevCertificates);
        this.updateAllStatus();
        this.applySorting();
        return;
      }
    } catch (e) {
      console.warn('Cant import localStorage certificates', e);
      router.navigate(['./openvpn/import']);
    }
    this.list = [];
  }

  public sortData(sort: Sort) {
    this.sort = sort;
    this.applySorting();
  }

  public applySorting(): void {
    if (this.sort) {
      this.list.sort(this.sorter(this.sort));
    }
    this.dataSource.data = [...this.list];
  }

  public findExisting(element: CreateCertificateBatchInfo): ClientCertificate | undefined {
    return this.clients.find(c => c.username === element.commonName);
  }

  public sorter(sort: Sort) {
    const rev1 = sort.direction === 'asc' ? 1 : -1;
    const rev2 = sort.direction === 'asc' ? -1 : 1;
    if (sort.active === 'status') {
      return (p1: CreateCertificateBatchInfo, p2: CreateCertificateBatchInfo) => {
        const a = p1.creationStatus ?? '';
        const b = p2.creationStatus ?? '';
        return a < b? rev1: (a > b? rev2: 0);
      };
    } else if (sort.active === 'commonName') {
      return (p1: CreateCertificateBatchInfo, p2: CreateCertificateBatchInfo) => {
        const a = p1.commonName;
        const b = p2.commonName;
        return a < b? rev1: (a > b? rev2: 0);
      };
    } else if (sort.active === 'email') {
      return (p1: CreateCertificateBatchInfo, p2: CreateCertificateBatchInfo) => {
        const a = p1.email ?? '';
        const b = p2.email ?? '';
        return a < b? rev1: (a > b? rev2: 0);
      };
    } else if (sort.active === 'staticAddress') {
      return (p1: CreateCertificateBatchInfo, p2: CreateCertificateBatchInfo) => {
        const a = p1.staticAddress;
        const b = p2.staticAddress;
        return a < b? rev1: (a > b? rev2: 0);
      };
    } else if (sort.active === 'identity') {
      return (p1: CreateCertificateBatchInfo, p2: CreateCertificateBatchInfo) => {
        const a = this.concatWs(' ', p1.country, p1.province, p1.city, p1.organisation, p1.organisationUnit) ?? '';
        const b = this.concatWs(' ', p2.country, p2.province, p2.city, p2.organisation, p2.organisationUnit) ?? '';
        return a < b? rev1: (a > b? rev2: 0);
      };
    } else {
      return (a: CreateCertificateBatchInfo, b: CreateCertificateBatchInfo) => a < b? rev1: (a > b? rev2: 0);
    }
  }

  private concatWs(sep: string, ...args: (string|undefined)[]): string|undefined {
    const usable = args.filter(c => c !== undefined);
    return usable.length ? usable.join(sep) : undefined;
  }

  public async downloadOpenvpnConfig(client: CreateCertificateBatchInfo): Promise<void> {
    try {
      const clientConfigFile = await this.openvpnService.loadClientConfig({username: client.commonName});
      saveAs(clientConfigFile, client.commonName + '.ovpn');
    } catch (e) {
      console.warn('Fail to download OVPN config file');
    }
  }

  private updateAllStatus(): void {
    const mayCreateProblem: CreateCertificateBatchInfo[] = [];
    this.list.forEach(s => this.updateStatus(s, mayCreateProblem));
  }

  private updateStatus(row: CreateCertificateBatchInfo, mayCreateProblem: CreateCertificateBatchInfo[]) {
    try {
      const existing = this.clients.find(c => c.username === row.commonName);
      if (existing) {

        if ((row.lastError = this.validateInfoFixable(row)) !== undefined) {
          row.creationStatus = 'conflict-fixable';
          return;
        }

        row.creationStatus = 'exists';
        row.lastError = 'Already exists';

        return;
      }
      const willExist = mayCreateProblem.find(c => c.commonName === row.commonName);
      if (willExist) {
        row.creationStatus = 'exists';
        row.lastError = 'Will exists';
        return;
      }

      if ((row.lastError = this.validateInfo(row, mayCreateProblem)) !== undefined) {
        row.creationStatus = 'invalid';
        return;
      }

      row.creationStatus = 'ready';
      mayCreateProblem.push(row);
    } catch (e) {
      console.warn('Cant determine status', e);
    }
  }

  public isUnknown(row: CreateCertificateBatchInfo) {
    return !row.creationStatus;
  }
  public isReady(row: CreateCertificateBatchInfo) {
    return row.creationStatus === 'ready';
  }

  public isInvalid(row: CreateCertificateBatchInfo) {
    return row.creationStatus === 'invalid';
  }

  public isPending(row: CreateCertificateBatchInfo) {
    return row.creationStatus === 'pending';
  }

  public isError(row: CreateCertificateBatchInfo) {
    return row.creationStatus === 'error';
  }

  public async cancel($event: Event): Promise<void> {
    $event.preventDefault();
    await this.router.navigate(['./openvpn/import']);
  }

  public async save(): Promise<void> {
    for (let i = 0; i < this.list.length; i++) {
      const batchInfo = this.list[i];

      try {
        await this.createCertificate(batchInfo);
        this.updateAllStatus();
      } catch (e) {
        console.warn('Error', e);
      }
    }
  }

  public async rotate(): Promise<void> {
    for (let i = 0; i < this.list.length; i++) {
      const batchInfo = this.list[i];
      if (batchInfo.creationStatus !== 'conflict-rotate') {
        continue;
      }

      try {
        const existing = this.clients.find(c => c.username === batchInfo.commonName);
        if (!existing) {
          console.warn('Cant find existing client yet with \'conflict-fixable\' status');
          continue;
        }
        await this.openvpnService.rotateCertificate(batchInfo.commonName, batchInfo);
        this.updateAllStatus();
      } catch (e) {
        console.warn('Error', e);
      }
    }
  }

  public async update(): Promise<void> {
    for (let i = 0; i < this.list.length; i++) {
      const batchInfo = this.list[i];
      if (batchInfo.creationStatus !== 'conflict-fixable') {
        continue;
      }

      try {
        const existing = this.clients.find(c => c.username === batchInfo.commonName);
        if (!existing) {
          console.warn('Cant find existing client yet with \'conflict-fixable\' status');
          continue;
        }
        const clientConfig: ClientConfig = new ClientConfig(batchInfo.staticAddress, existing.ccd?.customRoutes ?? [], existing.ccd?.customIRoutes ?? []);
        await this.openvpnService.saveClientConfig(existing, clientConfig);
        existing.ccd = clientConfig;
        this.updateAllStatus();
      } catch (e) {
        console.warn('Error', e);
      }
    }
  }

  public hasCreatableCertificates(): boolean {
    return !!this.list.find(create => !create.skip && create.creationStatus === 'ready');
  }

  public hasRotatableCertificates(): boolean {
    return !!this.list.find(create => !create.skip && create.creationStatus === 'conflict-rotate');
  }
  public hasUpdatableCertificates(): boolean {
    return !!this.list.find(create => !create.skip && create.creationStatus === 'conflict-fixable');
  }

  public setSkip(row: CreateCertificateBatchInfo): void {
    row.skip = true;
  }

  public setProcess(row: CreateCertificateBatchInfo): void {
    row.skip = false;
  }

  public async createClient(client: CreateCertificateBatchInfo): Promise<void> {
    await this.createCertificate(client);
    this.updateAllStatus();
  }

  public async editClient(client: CreateCertificateBatchInfo): Promise<void> {
    console.warn('edit client', client);
    try {
      // if (!client.ccd) {
      //     client.ccd = await this.openvpnService.loadClientConfigDetails(client.username);
      // }
      const updatedInfo = await this.modalService.open(CreateClientCertificateComponent, {
        size: 'lg',
        centered: true,
        injector: Injector.create({
          providers:[{
            provide: EditCertificatInfo,
            useValue: new EditCertificatInfo(client, 'return'),
          }],
          parent: this.injector,
        }),
      }).result as CertificatInfo | undefined;
      if (updatedInfo) {
        client.commonName = updatedInfo.commonName;
        client.email = updatedInfo.email;
        client.country = updatedInfo.country;
        client.province = updatedInfo.province;
        client.city = updatedInfo.city;
        client.organisation = updatedInfo.organisation;
        client.organisationUnit = updatedInfo.organisationUnit;
      }
      console.warn('client updated');
      this.updateAllStatus();
      this.applySorting();
    } catch (e) {
      console.warn('Cancel edit client', e);
    }
  }

  public identityEquals(row: BaseCertificate, certificate: BaseCertificate): boolean {
    // return BaseCertificate.equals();
    return row.email === certificate.email &&
      row.country === certificate?.country &&
      row.province === certificate?.province &&
      row.city === certificate?.city &&
      row.organisation === certificate?.organisation &&
      row.organisationUnit === certificate?.organisationUnit;
  }

  public titleIdentity(p1: BaseCertificate): string {
    return this.concatWs(' ', p1.country, p1.province, p1.city, p1.organisation, p1.organisationUnit) ?? '';
  }

  private validateInfoFixable(row: CreateCertificateBatchInfo): string | undefined {
    const existing = this.clients.find(c => c.username === row.commonName);
    if (existing && row.staticAddress) {
      if (existing.ccd?.clientAddress !== row.staticAddress) {
        return 'static address does not match: ' + existing.ccd?.clientAddress + ' => ' + row.staticAddress;
      }
    }
    return undefined;
  }

  private validateInfo(row: CreateCertificateBatchInfo, mayCreateProblem: CreateCertificateBatchInfo[]): string | undefined {
    if (!row.commonName.match(/^([a-zA-Z0-9_.\-@])+$/)) {
      return 'commonName invalid';
    }
    // if (!row.email?.length) {
    //   return 'email required';
    // }

    if (row.staticAddress) {
      const alreadyUsed = this.clients.find(c => c.ccd?.clientAddress === row.staticAddress);
      if (alreadyUsed) {
        return 'staticAddress already used by '+alreadyUsed.username;
      }
      const willExist = mayCreateProblem.find(c => c.staticAddress === row.staticAddress);
      if (willExist) {
        return 'staticAddress will already be assigned to '+willExist.commonName;
      }

      if (!this.openvpnService.isInNetwork(row.staticAddress, this.settings.server)) {
        return 'static address dont match server network '+this.settings.server;
      }
    }

    return undefined;
  }

  private async createCertificate(info: CreateCertificateBatchInfo) {
    if (info.skip) {
      console.warn('skip create =>', info);
      return;
    }
    if (info.creationStatus !== 'ready') {
      console.warn('skip ' + info.creationStatus + ' (' + info.lastError + ') =>', info);
      return;
    }
    try {
      info.processing = true;
      let clientCcd: ICcd | undefined;
      if (info.staticAddress) {
        clientCcd = {clientAddress: info.staticAddress, customRoutes: [], customIRoutes: []};
      }
      const client: ClientCertificate = await this.openvpnService.createClientCertificat({
        commonName: info.commonName,
        email: info.email,
        country: info.country,
        province: info.province,
        city: info.city,
        organisation: info.organisation,
        organisationUnit: info.organisationUnit,
        ccd: clientCcd,
      });
      this.clients.push(client);
      info.processing = false;
    } catch (e) {
      info.processing = false;
      throw e;
    }
  }
}
