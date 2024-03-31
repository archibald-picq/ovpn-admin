import {ICcd} from './client-certificate.interface';

export interface CreateCertificateDefinition {
  commonName: string;
  email: string;
  country: string;
  province: string;
  city: string;
  organisation: string;
  organisationUnit: string;
  ccd?: ICcd;
}
