import {Component, Injector} from '@angular/core';
import {OpenvpnService} from '../../services/openvpn.service';
import {ActivatedRoute, Router} from '@angular/router';
import {OpenvpnServiceConfig, ServerSetup} from '../../models/openvpn-config.model';
import {
  CreateClientCertificateComponent,
  EditCertificatInfo
} from '../../modals/create-client-certificate.component';
import {NgbModal} from '@ng-bootstrap/ng-bootstrap';
import {CertificatInfo} from '../../models/certificat-info.model';
import {Certificate} from '../../models/client-certificate.model';

class CertificatInfoViewModel implements CertificatInfo {
  exists = false;
  loading = false;
  error?: string;
  commonName = '';
  email?: string;
  country?: string;
  province?: string;
  city?: string;
  organisation?: string;
  organisationUnit?: string;
}

class DhPemViewModel {
  exists = false;
  loading = false;
  error?: string;
}

class SystemdServiceViewModel {
  exists = false;
  loading = false;
  error?: string;
  network = '10.5.0.0/24';
  port = '1194';
  state?: string;
}

class PkiInitViewModel {
  exists = false;
  loading = false;
  error?: string;
  count?: number;
}

function delay(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms));
}

@Component({
  selector: 'bus-openvpn-start-server',
  templateUrl: './create-server.component.html',
  styleUrls: ['./create-server.component.scss'],
})
export class CreateServerComponent {
  public error?: string;

  // Current config state from the server
  // note: we must update it according to what we do (http 2xx)
  public config: OpenvpnServiceConfig;
  public setup: ServerSetup;

  // UI states
  public loading = false;
  public pkiInit: PkiInitViewModel = new PkiInitViewModel();
  public authorityCertificate: CertificatInfoViewModel = new CertificatInfoViewModel();
  public serverCertificate: CertificatInfoViewModel = new CertificatInfoViewModel();
  public dhPem: DhPemViewModel = new DhPemViewModel();
  public systemdService: SystemdServiceViewModel = new SystemdServiceViewModel();

  public debugUi = document.cookie.indexOf('ovpnsetupdev=1')!==-1;

  constructor(
    private readonly openvpnService: OpenvpnService,
    private readonly router: Router,
    private readonly activatedRoute: ActivatedRoute,
    private readonly modalService: NgbModal,
    private readonly injector: Injector,
  ) {
    this.config = this.activatedRoute.snapshot.parent?.parent?.data.config;
    this.setup = this.config.serverSetup ?? ServerSetup.hydrate({
      serviceName: 'server',
      pkiPath: '/etc/openvpn/easyrsa/pki',
      dhPem: false,
      caCert: undefined,
      serverCert: undefined,
      pkiCount: undefined,
    });
    if (this.setup.pkiCount !== null && this.setup.pkiCount !== undefined) {
      this.pkiInit.exists = true;
      this.pkiInit.count = this.setup.pkiCount;
    }
    if (this.setup.caCert) {
      Certificate.copy(this.authorityCertificate, this.setup.caCert);
      this.authorityCertificate.exists = true;
    }
    if (this.setup.serverCert) {
      Certificate.copy(this.serverCertificate, this.setup.serverCert);
      this.serverCertificate.exists = true;
    }
    if (this.setup.dhPem) {
      this.dhPem.exists = true;
    }
    // console.warn('setup', this.setup);
    console.warn('debugUi', this.debugUi);
  }

  public async editAuthCert(event: Event) {
    console.warn('event', event);
    event.preventDefault();
    const updatedInfo = await this.modalService.open(CreateClientCertificateComponent, {
      centered: true,
      injector: Injector.create({
        providers:[{
          provide: EditCertificatInfo,
          useValue: new EditCertificatInfo(this.authorityCertificate, 'return', 'Authority Certificate'),
        }],
        parent: this.injector,
      }),
    }).result as CertificatInfo | undefined;
    console.warn('updated', updatedInfo);
    if (updatedInfo) {
      Certificate.copy(this.authorityCertificate, updatedInfo);
    }
  }

  public async editServerCert(event: Event) {
    console.warn('event', event);
    event.preventDefault();
    const updatedInfo = await this.modalService.open(CreateClientCertificateComponent, {
      centered: true,
      injector: Injector.create({
        providers:[{
          provide: EditCertificatInfo,
          useValue: new EditCertificatInfo(this.serverCertificate, 'return', 'Server Certificate'),
        }],
        parent: this.injector,
      }),
    }).result as CertificatInfo | undefined;
    console.warn('updated', updatedInfo);
    if (updatedInfo) {
      Certificate.copy(this.serverCertificate, updatedInfo);
    }
  }

  // public save() {
  //   this.error = undefined;
  //   this.loading = true;
  //   setTimeout(() => {
  //     this.config.unconfigured = false;
  //     this.loading = false;
  //     // this.config.serverCertUnconfigured = false;
  //     this.config.settings = Settings.parse({});
  //     console.warn('relative to', this.activatedRoute);
  //     this.router.navigate(['../../'], {relativeTo: this.activatedRoute /* skipLocationChange: true*/});
  //   }, 1000);
  // }
  public async save(): Promise<void> {
    if (this.loading) {
      console.warn('already processing');
      return;
    }
    await this.savePki();
    await this.saveAuthorityCertificate();
    await this.saveServerCertificate();
    await this.saveDiffieHellman();
    await this.saveSystemdService();

    if (this.pkiInit.exists && this.authorityCertificate.exists && this.serverCertificate.exists && this.dhPem.exists && this.systemdService.exists) {
      if (this.debugUi) {
        this.loading = false;
        console.warn('Stay on this page after process done during development');
      } else {
        await this.router.navigate(['../'] /* , {skipLocationChange: true}*/);
      }
    } else {
      this.loading = false;
      console.warn('Not fully OK');
    }
  }

  public async savePki(): Promise<void> {
    this.loading = true;

    // init the pki folder
    try {
      this.pkiInit.error = '';
      if (!this.pkiInit.exists) {
        this.pkiInit.loading = true;
        if (this.debugUi) {
          await delay(1000);
        } else {
          await this.openvpnService.initPki();
        }
        this.setup.pkiCount = 0;
        console.warn('pki initialized');
        this.pkiInit.exists = true;
      }
    } catch (e: any) {
      console.warn('raw error', e);
      this.pkiInit.error = this.wrapError(e);
    }
    this.pkiInit.loading = false;
  }

  public async saveAuthorityCertificate(): Promise<void> {

    // create authority certificate
    try {
      this.authorityCertificate.error = '';
      if (!this.pkiInit.exists) {
        this.authorityCertificate.error = 'Init PKI before creating CA';
      } else if (!this.authorityCertificate.exists) {
        if (!this.authorityCertificate.commonName) {
          throw {message: 'Missing commonName in certificate'};
        }
        this.authorityCertificate.loading = true;
        const cert = Certificate.build(this.authorityCertificate);
        if (this.debugUi) {
          await delay(1000);
          if (!cert.commonName) {
            throw {message: 'Invalid certificat'};
          }
        } else {
          await this.openvpnService.createCaCertificat(cert);
        }
        this.setup.caCert = cert;
        console.warn('ca cert created', cert);
        this.authorityCertificate.exists = true;
      }
    } catch (e: any) {
      console.warn('raw error', e);
      this.authorityCertificate.error = this.wrapError(e);
    }
    this.authorityCertificate.loading = false;
  }

  public async saveServerCertificate(): Promise<void> {
    // create server certificate
    try {
      this.serverCertificate.error = '';
      if (!this.authorityCertificate.exists) {
        this.serverCertificate.error = 'Create Authority Certificate before creating Server Certificate';
      } else if (!this.serverCertificate.exists) {
        if (!this.serverCertificate.commonName) {
          throw {message: 'Missing commonName in certificate'};
        }
        this.serverCertificate.loading = true;
        const cert = Certificate.build(this.serverCertificate);
        if (this.debugUi) {
          await delay(1000);
          if (!cert.commonName) {
            throw {message: 'Invalid certificat'};
          }
        } else {
          await this.openvpnService.createServerCertificat(cert);
        }
        this.setup.serverCert = cert;
        console.warn('server cert created', cert);
        this.serverCertificate.exists = true;
      }
    } catch (e: any) {
      console.warn('raw error', e);
      this.serverCertificate.error = this.wrapError(e);
    }
    this.serverCertificate.loading = false;
  }

  public async saveDiffieHellman(): Promise<void> {
    // create Diffie Hellman key
    try {
      this.dhPem.error = '';
      if (!this.pkiInit.exists) {
        this.dhPem.error = 'Init PKI before creating CA';
      } else if (!this.setup.dhPem) {
        this.dhPem.loading = true;
        if (this.debugUi) {
          await delay(5000);
        } else {
          await this.openvpnService.generateDh();
        }
        this.setup.dhPem = true;
      }
    } catch (e: any) {
      console.warn('raw error', e);
      this.dhPem.error = this.wrapError(e);
    }
    this.dhPem.loading = false;
  }

  public async saveSystemdService(): Promise<void> {
    // create systemd service
    try {
      this.systemdService.error = '';
      if (!this.serverCertificate.exists) {
        this.systemdService.error = 'Create Server certificate before starting OpenVPN server';
      } else if (!this.dhPem.exists) {
        this.systemdService.error = 'Generate Diffie Hellman key before starting OpenVPN server';
      } else {
        this.systemdService.loading = true;
        const toSave = {
          server: this.systemdService.network,
          port: this.systemdService.port,
          serverCertificate: this.serverCertificate.commonName,
        };
        if (this.debugUi) {
          await delay(1000);
        } else {
          const serviceConfig = await this.openvpnService.saveServiceConfig(this.setup.serviceName, toSave);
          console.warn('serviceConfig: ', serviceConfig);
          this.config.serverSetup = undefined;
          this.config.settings = serviceConfig;
        }
        this.systemdService.exists = true;
        this.systemdService.state = 'started';
      }
    } catch (e: any) {
      console.warn('raw error', e);
      this.systemdService.error = this.wrapError(e);
    }
    this.systemdService.loading = false;
  }

  private wrapError(e: any): string {
    return e.error?.message ? e.error.message: (e.message ?? e);
  }
}
