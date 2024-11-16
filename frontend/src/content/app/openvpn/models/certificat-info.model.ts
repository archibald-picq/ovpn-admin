import {BaseCertificate} from './certificate-base.interface';

export interface CertificatInfo extends BaseCertificate {
  commonName: string;
  expiresAt: Date | undefined;
  serialNumber: string | undefined;
}
