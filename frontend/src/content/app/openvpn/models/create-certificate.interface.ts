import {ICcd} from './client-certificate.interface';
import {BaseCertificate} from './certificate-base.interface';

export interface CreateCertificateDefinition extends BaseCertificate {
  commonName: string;
  ccd?: ICcd;
}
